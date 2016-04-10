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

import wx


## ################################################################# ##
## CLASS: ImportDialog
## ################################################################# ##

class ImportDialog(wx.Dialog):
    
    def __init__(self, parent, coordinator, cb_import):
        wx.Dialog.__init__(self, parent, -1, u'Import Results...', size=(600, 400), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        importPanel = Import_Panel(self, coordinator, cb_import)
        rootSizer = wx.BoxSizer()
        rootSizer.Add(importPanel, 1, wx.EXPAND)
        self.SetSizer(rootSizer)

class Import_Panel(wx.Panel):
    
    def __init__(self, parent, coordinator, cb_import):
        
        wx.Panel.__init__(self, parent)
        
        # Variables ##############################################
        self.__parent = parent
        self.__coordinator = coordinator
        self.__callback = cb_import
        hosts = self.__coordinator.get_info_results()
        ports = self.__coordinator.get_portscan_results()
        roots = self.__coordinator.get_spider_results()
        
        # Widgets ##############################################
        self.__hosts_list = wx.ListBox(self, -1, choices=hosts, style=wx.LB_MULTIPLE)
        self.__openPorts_list = wx.ListBox(self, -1, choices=ports, style=wx.LB_MULTIPLE)
        self.__roots_list = wx.ListBox(self, -1, choices=roots, style=wx.LB_MULTIPLE)
        self.__apply_button = wx.Button(self, wx.ID_APPLY, u'&Apply')
        self.__close_button = wx.Button(self, wx.ID_CLOSE, u'&Close')
        self.__command_text = wx.StaticText(self, -1, u'')
        
        # Event Bindings ##############################################
        self.Bind(wx.EVT_BUTTON, self.__onCloseButton, id=self.__close_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onApplyButton, id=self.__apply_button.GetId())
        listsSizerGrid = wx.GridBagSizer()
        listsSizerGrid.Add(wx.StaticText(self, -1, u'hosts:'), (0, 0), (1, 1), wx.ALIGN_BOTTOM | wx.ALIGN_LEFT | wx.LEFT, 5)
        listsSizerGrid.Add(wx.StaticText(self, -1, u'roots:'), (0, 1), (1, 1), wx.ALIGN_BOTTOM | wx.ALIGN_LEFT | wx.LEFT, 5)
        listsSizerGrid.Add(wx.StaticText(self, -1, u'ports:'), (0, 2), (1, 1), wx.ALIGN_BOTTOM | wx.ALIGN_LEFT | wx.LEFT, 5)
        listsSizerGrid.Add(self.__hosts_list, (1, 0), (1, 1), wx.EXPAND | wx.LEFT, 5)
        listsSizerGrid.Add(self.__roots_list, (1, 1), (1, 1), wx.EXPAND | wx.LEFT, 5)
        listsSizerGrid.Add(self.__openPorts_list, (1, 2), (1, 1), wx.EXPAND | wx.LEFT, 5)
        listsSizerGrid.AddGrowableCol(0)
        listsSizerGrid.AddGrowableCol(1)
        listsSizerGrid.AddGrowableRow(1)
        buttonGridSizer = wx.GridBagSizer()
        buttonGridSizer.Add(self.__command_text, (0, 0), (1, 1), wx.ALIGN_CENTER_VERTICAL)
        buttonGridSizer.Add(self.__close_button, (0, 1), (1, 1), wx.EXPAND)
        buttonGridSizer.Add(self.__apply_button, (0, 2), (1, 1), wx.EXPAND)
        buttonGridSizer.AddGrowableCol(0)
        rootSizer = wx.BoxSizer(wx.VERTICAL)
        rootSizer.Add(listsSizerGrid, 1, wx.EXPAND)
        rootSizer.Add(buttonGridSizer, 0, wx.EXPAND | wx.TOP, 5)
        self.SetSizer(rootSizer)
        
    def __onCloseButton(self, event):
        self.__parent.Close()
    
    def __onApplyButton(self, event):
        hosts_list = [self.__hosts_list.GetString(index) for index in self.__hosts_list.GetSelections()]
        ports_list = [self.__openPorts_list.GetString(index) for index in self.__openPorts_list.GetSelections()]
        roots_list = [self.__roots_list.GetString(index) for index in self.__roots_list.GetSelections()]
        hosts_string = u','.join(hosts_list)
        ports_string = u','.join(ports_list)
        roots_string = u','.join(roots_list)
        self.__callback(hosts_string, ports_string, roots_string)
        self.__parent.Close()