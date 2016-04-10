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

from webshag.core import core_utilities
from webshag.modules import module_spider

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

MODULE_SPIDER = 'spider'
REFRESH_RATE = 500
DEFAULT_PORT = '80'
DEFAULT_ROOT = '/'
TEXT_IDLE = u'Idle'
TEXT_LAST = u'Last run finished @ '
TEXT_RUNNING = u'Spider is currently running... '
TEXT_INVALID = u'Invalid Input !'

## ################################################################# ##
## CLASS: Spider_Panel
## ################################################################# ##

class Panel(wx.Panel):
    
    def __init__(self, parent, coordinator):
        
        wx.Panel.__init__(self, parent)
        self.__coordinator = coordinator
        
        # Variables #############################################
        self.__tool = MODULE_SPIDER
        self.__switch = [False]
        self.__switch_lock = threading.RLock()
        self.__results = []
        self.__displayedResults = []
        self.__results_lock = threading.RLock()
        
        # Widgets #############################################
        self.__hostText = wx.TextCtrl(self, -1, '')
        self.__portText = wx.TextCtrl(self, -1, DEFAULT_PORT)
        self.__rootText = wx.TextCtrl(self, -1, DEFAULT_ROOT)
        self.__okButton = wx.Button(self, wx.ID_OK, u'&OK')
        self.__stopButton = wx.Button(self, wx.ID_STOP, u'&Stop')
        self.__internalList = wx.ListBox(self, -1, style=wx.LB_SINGLE)
        self.__externalList = wx.ListBox(self, -1, style=wx.LB_SINGLE)
        self.__emailList = wx.ListBox(self, -1, style=wx.LB_SINGLE)
        self.__outputLogText = wx.TextCtrl(self, -1, '', style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.__statusText = wx.StaticText(self, -1, TEXT_IDLE)
        self.__timer = wx.Timer(self, -1)
        
        # Event Bindings #############################################
        self.Bind(wx.EVT_BUTTON, self.__onOKButton, id=self.__okButton.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onStopButton, id=self.__stopButton.GetId())
        self.Bind(wx.EVT_TIMER, self.__onTimer, id=self.__timer.GetId())
        
        # Layout Management #############################################
        rootSizer = wx.GridBagSizer()
        settingsSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Settings'), orient=wx.VERTICAL)
        resultSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Results'), orient=wx.VERTICAL)
        settingsSizerGrid = wx.GridBagSizer()
        resultSizerGrid = wx.GridBagSizer()
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Target [host | IPv4]:'), (0, 0), (1, 1), wx.ALIGN_BOTTOM)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Port [80]:'), (0, 1), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u'Start [/index.html]:'), (0, 2), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        settingsSizerGrid.Add(wx.StaticText(self, -1, u''), (0, 3), (1, 2), wx.EXPAND)
        settingsSizerGrid.Add(self.__hostText, (1, 0), (1, 1), wx.EXPAND)
        settingsSizerGrid.Add(self.__portText, (1, 1), (1, 1), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__rootText, (1, 2), (1, 1), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__okButton, (1, 3), (1, 1), wx.EXPAND | wx.LEFT, 5)
        settingsSizerGrid.Add(self.__stopButton, (1, 4), (1, 1), wx.EXPAND)
        settingsSizerGrid.AddGrowableCol(0)
        settingsSizerGrid.AddGrowableCol(2)
        
        resultSizerGrid.Add(wx.StaticText(self, -1, u'internal directories:'), (0, 0), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        resultSizerGrid.Add(self.__internalList, (1, 0), (5, 1), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.Add(wx.StaticText(self, -1, u'emails:'), (0, 1), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        resultSizerGrid.Add(self.__emailList, (1, 1), (2, 1), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.Add(wx.StaticText(self, -1, u'external links:'), (3, 1), (1, 1), wx.ALIGN_BOTTOM | wx.LEFT, 5)
        resultSizerGrid.Add(self.__externalList, (4, 1), (2, 1), wx.EXPAND | wx.ALL, 5)
        resultSizerGrid.Add(wx.StaticText(self, -1, u'Console:'), (6, 0), (1, 2), wx.LEFT | wx.ALIGN_BOTTOM, 5)
        resultSizerGrid.Add(self.__outputLogText, (7, 0), (1, 2), wx.EXPAND | wx.ALL, 5)
        
        resultSizerGrid.AddGrowableCol(0)
        resultSizerGrid.AddGrowableCol(1)
        resultSizerGrid.AddGrowableRow(1)
        resultSizerGrid.AddGrowableRow(2)
        resultSizerGrid.AddGrowableRow(4)
        resultSizerGrid.AddGrowableRow(5)
        resultSizerGrid.AddGrowableRow(7)
        
        settingsSizer.Add(settingsSizerGrid, 1, wx.EXPAND)
        resultSizer.Add(resultSizerGrid, 1, wx.EXPAND)
        
        statusSizer = wx.StaticBoxSizer(wx.StaticBox(self, -1, 'Status'), orient=wx.VERTICAL)
        statusSizer.Add(self.__statusText, 1, wx.EXPAND)
        
        rootSizer.Add(settingsSizer, (0, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(resultSizer, (1, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(statusSizer, (2, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.AddGrowableRow(1)
        rootSizer.AddGrowableCol(0)
        self.SetSizer(rootSizer)
    
    ## EVENT HANDLING METHODS ########################################## ##
    ## ################################################################# ##
    
    def __onStopButton(self, event):
        self.__end_scan()
        
    def __onOKButton(self, event):
        self.__start_scan()
    
    def __onTimer(self, event):
        with self.__switch_lock:
            if self.__switch[0]:
                self.__print_results(False)
            else:
                self.__print_results(True)
                self.__timer.Stop()
                self.__okButton.Enable(True)
                with self.__results_lock:
                    self.__coordinator.notify_stop(self.__tool, self.__displayedResults)
    
    ## DISPLAY RELATED METHODS ######################################### ##
    ## ################################################################# ##
    
    def __print_start(self):
        self.__internalList.Clear()
        self.__externalList.Clear()
        self.__emailList.Clear()
        self.__outputLogText.Clear()
        self.__statusText.SetLabel(TEXT_RUNNING)

    def __print_invalid(self):
        self.__internalList.Clear()
        self.__externalList.Clear()
        self.__emailList.Clear()
        self.__outputLogText.Clear()
        self.__statusText.SetLabel(TEXT_INVALID)

    def __print_results(self, finished):
        tmpRes = []
        
        with self.__results_lock:
            
            while len(self.__results) > 0:
                rs = self.__results.pop(0)
                tmpRes.append(rs)
                self.__displayedResults.append(rs)
                
        for result in tmpRes:
            
            if result.has_key(u'ERROR'):
                self.__outputLogText.AppendText( u'ERROR\t' + result[u'ERROR'] + u'\n')
                
            elif result.has_key(u'TARGET'):
                self.__outputLogText.AppendText( u'INFO\tSpidering ' + result[u'TARGET'] + u'\n')
               
            elif result.has_key(u'INTERNAL'):
                self.__internalList.AppendAndEnsureVisible(result[u'INTERNAL'])
                
            elif result.has_key(u'EXTERNAL'):
                self.__externalList.AppendAndEnsureVisible(result[u'EXTERNAL'])
                
            elif result.has_key(u'EMAIL'):
                self.__emailList.AppendAndEnsureVisible(result[u'EMAIL'])
                
        if finished:
            self.__statusText.SetLabel(TEXT_IDLE + u'. ' + TEXT_LAST + strftime("%d/%m/%Y %H:%M:%S", localtime()))
    
    ## MISC METHODS #################################################### ##
    ## ################################################################# ##
    
    def __start_scan(self):
        with self.__switch_lock:
            if not self.__switch[0]:
                self.__load_entries()
                if self.__check_entries():
                    self.__coordinator.notify_start(self.__tool)
                    self.__switch[0] = True
                    self.__okButton.Enable(False)
                    self.__results = []
                    self.__internal = []
                    self.__external = []
                    self.__email = []
                    self.__displayedResults = []
                    self.__print_start()
                    Thread(self.__host, self.__port, self.__root, self.__results, self.__results_lock, self.__switch, self.__switch_lock, self.callback_end).start()
                    self.__timer.Start(REFRESH_RATE*2)
                else:
                    self.__print_invalid()
            else:
                pass
    
    def __end_scan(self):
        with self.__switch_lock:
            self.__switch[0] = False
    
    def __load_entries(self):
        self.__host = self.__hostText.GetValue().strip()
        self.__port = self.__portText.GetValue().strip()
        self.__root = self.__rootText.GetValue().strip()
    
    def __check_entries(self):
        return core_utilities.check_host(self.__host) and core_utilities.check_port_string(self.__port) and core_utilities.check_spider_root(self.__root)
    
    def callback_end(self):
        self.__end_scan()
        

## ################################################################# ##
## CLASS: Spider_Thread
## ################################################################# ##

class Thread(threading.Thread):
    
    def __init__(self, host, port, root, results, results_lock, switch, switch_lock, cb_end):
        threading.Thread.__init__(self)
        self.__host = host
        self.__port = port
        self.__root = root
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        self.__cb_end = cb_end
    
    def run(self):
        module_spider.perform(self.__host, int(self.__port), self.__root, False, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        self.__cb_end()

