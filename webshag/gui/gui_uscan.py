# -*- coding: utf-8 -*-
## ################################################################# ##
## (C) SCRT - Information Security, 2007 - 2008 // author: ~SaD~     ##
## ################################################################# ##
## This program is free software: you can redistribute it and/or     ##
## modify it under the terms of the GNU General Public License as    ##
## published by the Free Software Foundation, either version 3 of    ##
## the License, or (at your option) any later version.               ##
## This program is distributed in the hope that it will be useful,   ##
## but WITHOUT ANY WARRANTY; without even the implied warranty of    ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the     ##
## GNU General Public License for more details.                      ##
## You should have received a copy of the GNU General Public License ##
## along with this program. If not, see http://www.gnu.org/licenses. ##
## ################################################################# ##
## last mod: 2008-11-03

from __future__ import with_statement
import wx
import threading
from time import strftime, localtime

import gui_widgets
from webshag.core import core_utilities, core_file, core_error
from webshag.modules import module_uscan

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

MODULE_USCAN = 'uscan'
REFRESH_RATE = 50
DEFAULT_PORT = '80'
DEFAULT_ROOT = '/'
AUTO_WEB_SERVER = u'-- automatic --'
TEXT_IDLE = u'Idle'
TEXT_LAST = u'Last run finished @ '
TEXT_RUNNING = u'Running : '
TEXT_INVALID = u'Invalid Input !'

## ################################################################# ##
## CLASS: Panel
## ################################################################# ##

class Panel(wx.Panel):
    
    def __init__(self, parent, coordinator):
        
        wx.Panel.__init__(self, parent)
        self.__coordinator = coordinator
        
        # Variables #############################################
        self.__tool = MODULE_USCAN
        self.__switch = [False]
        self.__results = []
        self.__targets = {}
        self.__exportableResults = []
        self.__switch_lock = threading.RLock()
        self.__results_lock = threading.RLock()
        self.__currentTarget = ''
        
        # Widgets ##############################################
        self.__timer = wx.Timer(self, -1)
        self.__hostsText = wx.TextCtrl(self, -1, '')
        self.__portsText = wx.TextCtrl(self, -1, DEFAULT_PORT)
        self.__rootsText = wx.TextCtrl(self, -1, DEFAULT_ROOT)
        self.__skipText = wx.TextCtrl(self, -1, '')
        self.__server_choices = [AUTO_WEB_SERVER]
        
        try:
            tmp_choices = []
            tmp_banners = core_file.db_load_known_banners()
            for tmp in tmp_banners.values():
                if tmp not in tmp_choices:
                    tmp_choices.append(tmp)
            tmp_choices.sort()
            self.__server_choices.extend(tmp_choices)
        except core_error.Config_Error, e:
            pass
        
        self.__serverCombo = wx.ComboBox(self, -1, style=wx.CB_READONLY, choices=self.__server_choices)
        self.__serverCombo.SetValue(self.__server_choices[0])
        self.__importButton = wx.Button(self, -1, u'Import...')
        self.__okButton = wx.Button(self, wx.ID_OK, u'&OK')
        self.__stopButton = wx.Button(self, wx.ID_STOP, u'&Stop')
        
        self.__outputTargetList = wx.ListBox(self, -1, style=wx.LB_SINGLE)
        self.__outputTargetText = wx.TextCtrl(self, -1, '', style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
        self.__outputLogText = wx.TextCtrl(self, -1, '', style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.__statusText = wx.StaticText(self, -1, TEXT_IDLE)
        
        
        # Event Bindings ################################################################
        self.Bind(wx.EVT_BUTTON, self.__onOKButton, id=self.__okButton.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onStopButton, id=self.__stopButton.GetId())
        self.Bind(wx.EVT_TIMER, self.__onTimer, id=self.__timer.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onImport, id=self.__importButton.GetId())
        self.Bind(wx.EVT_LISTBOX, self.__onTargetSelect, id=self.__outputTargetList.GetId())
        
        # Layout Management #############################################################
        settingsSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Settings'), orient=wx.VERTICAL)
        settingsSizerGrid = wx.GridBagSizer()
        settingsSizerGrid.AddGrowableCol(0)
        settingsSizerGrid.AddGrowableCol(1)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Target(s) [host1, host2,...]:'), (0, 0), (1, 2), wx.ALIGN_BOTTOM | wx.TOP, 5)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Port(s) [80, 8080,...]:'), (0, 2), (1, 1), wx.ALIGN_BOTTOM | wx.TOP | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__hostsText, (1, 0), (1, 2), wx.EXPAND)
        settingsSizerGrid.Add(self.__portsText, (1, 2), (1, 1), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__okButton, (1, 3), (1, 1), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__stopButton, (1, 4), (1, 1), wx.EXPAND)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Root directoties [/, /dir/,...]:'), (2, 0), (1, 1), wx.ALIGN_BOTTOM)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Skip String [Not Found]:'), (2, 1), (1, 2), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__importButton, (2, 3), (1, 2), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__rootsText, (3, 0), (1, 1), wx.EXPAND)
        settingsSizerGrid.Add(self.__skipText, (3, 1), (1, 2), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__serverCombo, (3, 3), (1, 2), wx.EXPAND | wx.LEFT, 5)
        settingsSizer.Add(settingsSizerGrid, 1, wx.EXPAND)
       
        resultSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Results'), orient=wx.VERTICAL)
        resultSizerGrid = wx.GridBagSizer()
        resultSizerGrid.Add(wx.StaticText(self, -1, u'Targets:'), (0, 0), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        resultSizerGrid.Add(self.__outputTargetList, (1, 0), (3, 1), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.Add(wx.StaticText(self, -1, u'Results:'), (0, 1), (1, 4), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        resultSizerGrid.Add(self.__outputTargetText, (1, 1), (3, 4), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.Add(wx.StaticText(self, -1, u'Console:'), (4, 0), (1, 5), wx.LEFT | wx.ALIGN_BOTTOM, 5)
        resultSizerGrid.Add(self.__outputLogText, (5, 0), (1, 5), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.AddGrowableCol(0)
        resultSizerGrid.AddGrowableCol(1)
        resultSizerGrid.AddGrowableCol(2)
        resultSizerGrid.AddGrowableCol(3)
        resultSizerGrid.AddGrowableCol(4)
        resultSizerGrid.AddGrowableRow(1)
        resultSizerGrid.AddGrowableRow(2)
        resultSizerGrid.AddGrowableRow(3)
        resultSizerGrid.AddGrowableRow(5)
        
        resultSizer.Add(resultSizerGrid, 1, wx.EXPAND)
        
        statusSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Status'), orient=wx.VERTICAL)
        statusSizer.Add(self.__statusText, 1, wx.EXPAND)
        
        rootSizer = wx.GridBagSizer()
        rootSizer.Add(settingsSizer, (0, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(resultSizer, (1, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(statusSizer, (2, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.AddGrowableRow(1)
        rootSizer.AddGrowableCol(0)
        self.SetSizer(rootSizer)
    
    ## EVENT HANDLING METHODS ########################################## ##
    ## ################################################################# ##
    
    def __onTargetSelect(self, event):
        tgt = self.__outputTargetList.GetString(self.__outputTargetList.GetSelection())
        if self.__targets.has_key(tgt):
            self.__outputTargetText.SetValue(self.__targets[tgt])
        else:
            self.__outputTargetText.Clear()
    
    def __onTimer(self, event):
        with self.__switch_lock:
            if self.__switch[0]:
                self.__print_results(False)
            else:
                self.__timer.Stop()
                self.__print_results(True)
                self.__okButton.Enable(True)
                self.__outputTargetList.Enable(True)
                self.__coordinator.notify_stop(self.__tool, self.__exportableResults)
    
    def __onStopButton(self, event):
        self.__end_scan()

    def __onOKButton(self, event):
        self.__start_scan()

    def __onImport(self, event):
        iWindow = gui_widgets.ImportDialog(self, self.__coordinator, self.callback_import)
        iWindow.ShowModal()
        iWindow.Destroy()
    
    ## DISPLAY RELATED METHODS ######################################### ##
    ## ################################################################# ##
    
    def __print_start(self):
        self.__outputTargetList.Clear()
        self.__outputTargetText.Clear()
        self.__outputLogText.Clear()
        self.__statusText.SetLabel(TEXT_RUNNING)
    
    def __print_invalid(self):
        self.__outputTargetList.Clear()
        self.__outputTargetText.Clear()
        self.__outputLogText.Clear()
        self.__statusText.SetLabel(TEXT_INVALID)
    
    def __print_results(self, finished):
        
        tmpRes = []
        
        with self.__results_lock:
            while len(self.__results) > 0:
                rs = self.__results.pop(0)
                tmpRes.append(rs)
                
        for result in tmpRes:
                
            if result.has_key(u'ERROR'):
                if result.has_key(u'HOST') and result.has_key(u'PORT'):
                    tgt = result[u'HOST'] + u':' + result[u'PORT']
                    if self.__targets.has_key(tgt):
                        self.__targets[tgt] += u'\n[ERR]\t' + result[u'ERROR'] + u'\n'
                        if self.__currentTarget == tgt:
                            self.__outputTargetText.AppendText(u'\n[ERR]\t' + result[u'ERROR'] + u'\n')
                            self.__outputTargetText.ShowPosition(self.__outputTargetText.GetLastPosition())
                    else:
                        self.__outputLogText.AppendText( u'ERROR\t' + result[u'ERROR'] + u'\n')
                else:
                    self.__outputLogText.AppendText(u'ERROR\t' + result[u'ERROR'] + u'\n')
            
            elif result.has_key(u'TARGET'):
                tgt = result[u'HOST'] + u':' + result[u'PORT']
                # add new target #
                self.__targets[tgt] = u''
                self.__currentTarget = tgt
                self.__outputTargetText.Clear()
                self.__outputLogText.AppendText( u'TARGET\tScanning ' + result[u'TARGET'] + u'\n')
                self.__outputTargetList.AppendAndEnsureVisible(tgt)
            
            elif result.has_key(u'INFO'):
                tgt = result[u'HOST'] + u':' + result[u'PORT']
                if self.__targets.has_key(tgt):
                    self.__targets[tgt] += u'\n[INF]\t' + result[u'INFO'] + u'\n'
                    if self.__currentTarget == tgt:
                        self.__outputTargetText.AppendText(u'\n[INF]\t' + result[u'INFO'] + u'\n')
                        self.__outputTargetText.ShowPosition(self.__outputTargetText.GetLastPosition())
                else:
                    self.__outputLogText.AppendText(u'INFO\t' + result[u'INFO'] + u'\n')
            
            elif result.has_key(u'BANNER'):
                tgt = result[u'HOST'] + u':' + result[u'PORT']
                if self.__targets.has_key(tgt):
                    self.__targets[tgt] += u'\n[SRV]\t' + result[u'BANNER'] + u' ==> ' + result[u'SERVER'] + u'\n'
                    if self.__currentTarget == tgt:
                        self.__outputTargetText.AppendText(u'\n[SRV]\t' + result[u'BANNER'] + u' ==> ' + result[u'SERVER'] + u'\n')
                        self.__outputTargetText.ShowPosition(self.__outputTargetText.GetLastPosition())
                else:
                    self.__outputLogText.AppendText(u'SERVER\tServer Banner (' + result[u'HOST'] + u' : ' +result[u'PORT'] + u'): ' + result[u'BANNER'] + u' (' + result[u'SERVER'] + u')\n')
                
                self.__exportableResults.append(result)
                
            elif result.has_key(u'MISS'):
                
                if len(result[u'MISS']) < 50:    
                    self.__statusText.SetLabel(TEXT_RUNNING + u' ' + result[u'MISS'].replace(u'\n', u'\\n'))
                    
                else:
                    label = result[u'MISS'][0:20] + u' ... ' + result[u'MISS'][-20:]
                    self.__statusText.SetLabel(TEXT_RUNNING + u' ' + label.replace(u'\n', u'\\n'))
                
            else:
                tgt = result[u'HOST'] + u':' + result[u'PORT']
                text = u'\n[' + result[u'CODE'] + u']\t' + result[u'PATH'] + u'\n' + result[u'DESCRIPTION'] + u'\n'
                if self.__targets.has_key(tgt):
                    self.__targets[tgt] += text
                    if self.__currentTarget == tgt:
                        self.__outputTargetText.AppendText(text)
                        self.__outputTargetText.ShowPosition(self.__outputTargetText.GetLastPosition())
                
                self.__exportableResults.append(result)
        
        if finished:
            self.__statusText.SetLabel(TEXT_IDLE + u'. ' + TEXT_LAST + strftime("%d/%m/%Y %H:%M:%S", localtime()))
    
    ## MISC METHODS #################################################### ##
    ## ################################################################# ##
    
    def __start_scan(self):
        with self.__switch_lock:
            if not self.__switch[0]:
                self.__load_entries()
                if self.__check_entries():
                    self.__switch[0] = True
                    self.__coordinator.notify_start(self.__tool)
                    self.__outputTargetList.Enable(False)
                    self.__okButton.Enable(False)
                    self.__results = []
                    self.__targets = {}
                    self.__currentTarget = u''
                    self.__exportableResults = []
                    self.__print_start()
                    Thread(self.__hosts, self.__ports, self.__roots, self.__server, self.__skip, self.__results, self.__results_lock, self.__switch, self.__switch_lock, self.callback_end).start()
                    self.__timer.Start(REFRESH_RATE)
                else:
                    self.__print_invalid()
            else:
                pass
    
    def __end_scan(self):
        with self.__switch_lock:
            self.__switch[0] = False
    
    def __load_entries(self):
        self.__hosts = self.__hostsText.GetValue().strip()
        self.__ports = self.__portsText.GetValue().strip()
        self.__roots = self.__rootsText.GetValue().strip()
        if self.__serverCombo.GetValue() != AUTO_WEB_SERVER:
            self.__server = self.__serverCombo.GetValue()
        else:
            self.__server = u''
        self.__skip = self.__skipText.GetValue().strip()
    
    def __check_entries(self):
        return core_utilities.check_host_list(self.__hosts) and core_utilities.check_port_list(self.__ports) and core_utilities.check_root_list(self.__roots) and core_utilities.check_generic_string(self.__skip)

    def enable(self, state):
        self.__importButton.Enable(state)

    def callback_end(self):
        self.__end_scan()
    
    def callback_import(self, hosts, ports, roots):
        if hosts != u'':
            self.__hostsText.SetValue(hosts)
        if ports != u'':
            self.__portsText.SetValue(ports)
        if roots != u'':
            self.__rootsText.SetValue(roots)
    

## ################################################################# ##
## CLASS: Url_Scanner_Thread
## ################################################################# ##

class Thread(threading.Thread):
    
    def __init__(self, hosts, ports, roots, server, skip, results, results_lock, switch, switch_lock, cb_end):
        
        threading.Thread.__init__(self)
        self.__hosts = hosts
        self.__ports = ports
        self.__roots = roots
        self.__server = server
        self.__skip = skip
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        self.__cb_end = cb_end
    
    def run(self):
        
        hosts = [h.strip() for h in self.__hosts.split(u',')]
        ports = [int(p.strip()) for p in self.__ports.split(u',')]
        roots = [r.strip() for r in self.__roots.split(u',')]
        results = module_uscan.perform(hosts, ports, roots, self.__server, self.__skip, False, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        self.__cb_end()