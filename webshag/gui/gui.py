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
from sys import exit
from webshag.core import core_utilities, core_file, core_error
from webshag.export import export
from webshag.update import update

import gui_pscan
import gui_info
import gui_spider
import gui_uscan
import gui_fuzz
import gui_images

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

WEBSHAG = u'webshag'
WEBSHAG_VERSION = u'1.10'

SPLASH_TIME = 1500

MODULE_PSCAN = 'pscan'
MODULE_INFO = 'info'
MODULE_SPIDER = 'spider'
MODULE_USCAN = 'uscan'
MODULE_FUZZ = 'fuzz'

ABOUT_DESCRIPTION = u'"shagadelic" web server audit tool ;-)'
ABOUT_LICENSE = u"""
This program is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see http://www.gnu.org/licenses.
"""
ABOUT_WEBSITE = u'http://www.scrt.ch'
ABOUT_COPY = u'(c) SCRT - Information Security, 2007-2008'
ABOUT_ME = u'Author: ~SaD~'

EXPORT_FORMATS = [u'xml', u'html', 'txt']

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##

def run():
    app = WebshagGUI(redirect=False)
    app.MainLoop()

## ################################################################# ##
## CLASS: WebshagGUI
## ################################################################# ##
## This class is in charge of launching the webshag GUI
## ################################################################# ##
class WebshagGUI(wx.App):
    
    def OnInit(self):
        splash = webshagSplash()
        splash.Show()
        window = WebshagWindow(None, -1, WEBSHAG + ' ' + WEBSHAG_VERSION)
        return True

## ################################################################# ##
## CLASS: WebshagSplash
## ################################################################# ##
## This class implements the splash screen
## ################################################################# ##
class webshagSplash(wx.SplashScreen):
    
    def __init__(self):
        splashImage = gui_images.getSplashBitmap()
        wx.SplashScreen.__init__(self, splashImage, wx.SPLASH_CENTRE_ON_SCREEN | wx.SPLASH_TIMEOUT, SPLASH_TIME, None)
        wx.Yield()

## ################################################################# ##
## CLASS: WebshagWindow
## ################################################################# ##
## This class implements the main window of the GUI
## ################################################################# ##
class WebshagWindow(wx.Frame):
    
    def __init__(self, parent, id, title):
        
        self.__frameWidth = wx.DisplaySize()[0] / 1.5
        self.__frameHeight = wx.DisplaySize()[1] / 1.5
        wx.Frame.__init__(self, parent, id, title, size=(self.__frameWidth, self.__frameHeight))

        # window icon
        icon = gui_images.geticonIcon()
        self.SetIcon(icon)
        
        # Variables ############################################
        self.__tool_running = {}
        self.__tool_running[MODULE_INFO] = False
        self.__tool_running[MODULE_USCAN] = False
        self.__tool_running[MODULE_FUZZ] = False
        self.__tool_running[MODULE_SPIDER] = False
        self.__tool_running[MODULE_PSCAN] = False
        self.__tool_results = {}
        self.__tool_results[MODULE_INFO] = []
        self.__tool_results[MODULE_USCAN] = []
        self.__tool_results[MODULE_FUZZ] = []
        self.__tool_results[MODULE_SPIDER] = []
        self.__tool_results[MODULE_PSCAN] = []
        self.__tool_lock = threading.RLock()
        
        # Widgets ############################################## 
        #
        # MENU BAR #
        self.__menuBar = wx.MenuBar()
        fileMenu = wx.Menu()
        self.__fileExportItem = wx.MenuItem(fileMenu, -1, u'&Export...')
        fileMenu.AppendItem(self.__fileExportItem)
        fileMenu.AppendSeparator()
        fileQuitItem = wx.MenuItem(fileMenu, -1, u'&Quit\tCtrl+Q')
        fileMenu.AppendItem(fileQuitItem)
        self.__menuBar.Append(fileMenu, u'&File')
        toolsMenu = wx.Menu()
        self.__toolsConfigItem = wx.MenuItem(toolsMenu, -1, u'&Config...')
        toolsMenu.AppendItem(self.__toolsConfigItem)
        updateMenu = wx.Menu()
        self.__updateNiktoItem = wx.MenuItem(updateMenu, -1, u'Nikto Database')
        updateMenu.AppendItem(self.__updateNiktoItem)
        self.__updateCustomItem = wx.MenuItem(updateMenu, -1, u'SCRT Database')
        updateMenu.AppendItem(self.__updateCustomItem)
        toolsMenu.AppendMenu(-1, '&Update', updateMenu)
        self.__menuBar.Append(toolsMenu, u'&Tools')
        helpMenu = wx.Menu()
        helpAboutItem = wx.MenuItem(helpMenu, -1, u'&About')
        helpMenu.AppendItem(helpAboutItem)
        self.__menuBar.Append(helpMenu, u'&Help')
        self.SetMenuBar(self.__menuBar)
        #
        # NOTEBOOK #
        self.__notebook = wx.Notebook(self, -1)
        self.__infoPanel = gui_info.Panel(self.__notebook, self)
        self.__openPortscanPanel = gui_pscan.Panel(self.__notebook, self)
        self.__spiderPanel = gui_spider.Panel(self.__notebook, self)
        self.__urlScannerPanel = gui_uscan.Panel(self.__notebook, self) 
        self.__fuzzerPanel = gui_fuzz.Panel(self.__notebook, self)
        
        self.__notebook.AddPage(self.__openPortscanPanel, 'PSCAN')
        self.__notebook.AddPage(self.__infoPanel, 'INFO')
        self.__notebook.AddPage(self.__spiderPanel, 'SPIDER')
        self.__notebook.AddPage(self.__urlScannerPanel, 'USCAN')
        self.__notebook.AddPage(self.__fuzzerPanel, 'FUZZ')
        
        # Event Bindings #######################################
        self.Bind(wx.EVT_MENU, self.__onQuit, id=fileQuitItem.GetId())
        self.Bind(wx.EVT_MENU, self.__onExport, id=self.__fileExportItem.GetId())
        self.Bind(wx.EVT_MENU, self.__onAbout, id=helpAboutItem.GetId())
        self.Bind(wx.EVT_MENU, self.__onConfig, id=self.__toolsConfigItem.GetId())
        self.Bind(wx.EVT_MENU, self.__onNiktoUpdate, id=self.__updateNiktoItem.GetId())
        self.Bind(wx.EVT_MENU, self.__onCustomUpdate, id=self.__updateCustomItem.GetId())
        self.Bind(wx.EVT_WINDOW_DESTROY, self.__onQuit)
        
        # Layout Management ####################################
        rootSizer = wx.BoxSizer(wx.VERTICAL)
        rootSizer.Add(self.__notebook, 1, wx.EXPAND)
        self.SetSizer(rootSizer)
        
        self.Center()
        self.Show(True)

    ## EVENT HANDLING METHODS ########################################## ##
    ## ################################################################# ##

    def __onQuit(self, event):
        self.Close(True)
        exit(0)
    
    def __onAbout(self, event):
        
        about = wx.AboutDialogInfo()
        about.SetIcon(gui_images.getSCRTIcon())
        about.SetWebSite(ABOUT_WEBSITE)
        about.SetCopyright(ABOUT_COPY)
        about.SetName(WEBSHAG)
        about.SetVersion(WEBSHAG_VERSION)
        about.SetDescription(ABOUT_DESCRIPTION)
        about.SetLicence(ABOUT_LICENSE)
        about.AddDeveloper(ABOUT_ME)
        about.AddDocWriter(ABOUT_ME)
        wx.AboutBox(about)
    
    def __onConfig(self, event):
        cfWindow = ConfigDialog(self, -1, u'Configuration')
        cfWindow.ShowModal()
        cfWindow.Destroy()
    
    def __onExport(self, event):
        results = {}
        with self.__tool_lock:
            for key in self.__tool_results.keys():
                if self.__tool_results[key] != []:
                    results[key] = self.__tool_results[key][:]
                else:
                    results[key] = None
        
        exWindow = ExportDialog(self, results)
        exWindow.ShowModal()
        exWindow.Destroy()
    
    def __onNiktoUpdate(self, event):
        success = update.update_nikto_database()
        if success:
            wx.MessageDialog(self, u'Update of Nikto database succeded!', style=wx.OK | wx.ICON_INFORMATION | wx.CENTRE).ShowModal()
        else:
            wx.MessageDialog(self, u'Update of Nikto database failed!', style=wx.OK | wx.ICON_ERROR | wx.CENTRE).ShowModal()
    
    def __onCustomUpdate(self, event):
        success = update.update_custom_database()
        if success:
            wx.MessageDialog(self, u'Update of SCRT database succeded!', style=wx.OK | wx.ICON_INFORMATION | wx.CENTRE).ShowModal()
        else:
            wx.MessageDialog(self, u'Update of SCRT database failed!', style=wx.OK | wx.ICON_ERROR | wx.CENTRE).ShowModal()
    
    
    ## COORDINATOR METHODS ############################################# ##
    ## ################################################################# ##
    ## The methods below are called by the tool panels. Indeed, the main
    ## window is in charge of coordinating the various tools (for
    ## instance preventing config file to be edited while some tool is
    ## running). For this reason, the instance of the main window is
    ## passed to tool panels as coordinator. Note that a dedicated class
    ## could be used as coordinator but there is no need for that.
    ## ################################################################# ##
    
    def __toolRunning(self):
        self.__toolsConfigItem.Enable(False)
        self.__updateNiktoItem.Enable(False)
        self.__updateCustomItem.Enable(False)
        self.__fileExportItem.Enable(False)
        self.__urlScannerPanel.enable(False)
        self.__fuzzerPanel.enable(False)

    def __noToolRunning(self):
        self.__toolsConfigItem.Enable(True)
        self.__updateNiktoItem.Enable(True)
        self.__updateCustomItem.Enable(True)
        self.__fileExportItem.Enable(True)
        self.__urlScannerPanel.enable(True)
        self.__fuzzerPanel.enable(True)
    
    def notify_start(self, tool):
        with self.__tool_lock:
            self.__tool_running[tool] = True
            self.__tool_results[tool] = []
            self.__toolRunning()
    
    def notify_stop(self, tool, results):
        with self.__tool_lock:
            self.__tool_running[tool] = False
            self.__tool_results[tool] = results
            if not True in self.__tool_running.values():
                self.__noToolRunning()

    def get_portscan_results(self):
        results = []
        with self.__tool_lock:
            for result in self.__tool_results[MODULE_PSCAN]:
                if result.has_key(u'PORTID'):
                    results.append(result[u'PORTID'])
        return results
    
    def get_info_results(self):
        results = []
        with self.__tool_lock:
            for result in self.__tool_results[MODULE_INFO]:
                if result.has_key(u'VHOST'):
                    results.append(result[u'VHOST'])
        return results
    
    def get_spider_results(self):
        results = []
        with self.__tool_lock:
            for result in self.__tool_results[MODULE_SPIDER]:
                if result.has_key(u'INTERNAL'):
                    results.append(result[u'INTERNAL'])
        return results

## ################################################################# ##
## CLASS: ConfigDialog
## ################################################################# ##
## This class displays the configuration editor dialog
## ################################################################# ##
class ConfigDialog(wx.Dialog):
    
    def __init__(self, parent, id, title):
        wx.Dialog.__init__(self, parent, id, title, size=(600, 600), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        cfgPanel = Config_Panel(self)
        rootSizer = wx.BoxSizer()
        rootSizer.Add(cfgPanel, 1, wx.EXPAND)
        self.SetSizer(rootSizer)


## ################################################################# ##
## CLASS: Config_Panel
## ################################################################# ##
## This class provides a GUI for editing config file
## ################################################################# ##
class Config_Panel(wx.ScrolledWindow):
    
    def __init__(self, parent):
        
        wx.ScrolledWindow.__init__(self, parent)
        self.__parent = parent
        self.SetScrollbars(20, 20, 55, 40)
        
        # Widgets ##############################################
        # HTTP Settings #
        self.__socket_timeout_spin = wx.SpinCtrl(self, -1)
        self.__socket_timeout_spin.SetRange(1, 30)
        self.__ssl_check = wx.CheckBox(self, -1, u'Enable SSL')
        self.__user_agent_text = wx.TextCtrl(self, -1)
        self.__auth_check = wx.CheckBox(self, -1, u'Enable HTTP Authentication')
        self.__auth_username_text = wx.TextCtrl(self, -1)
        self.__auth_password_text = wx.TextCtrl(self, -1)
        self.__proxy_check = wx.CheckBox(self, -1, u'Enable HTTP Proxy')
        self.__proxy_host_text = wx.TextCtrl(self, -1)
        self.__proxy_port_text = wx.TextCtrl(self, -1)
        self.__proxy_auth_check = wx.CheckBox(self, -1, u'Enable HTTP Proxy Authentication')
        self.__proxy_username_text = wx.TextCtrl(self, -1)
        self.__proxy_password_text = wx.TextCtrl(self, -1)
        self.__ids_check = wx.CheckBox(self, -1, u'Enable IDS Evasion')
        self.__ids_rp_check = wx.CheckBox(self, -1, u'Random Proxy')
        self.__ids_rp_list_text = wx.TextCtrl(self, -1)
        self.__ids_rp_list_button = wx.Button(self, -1, u'...')
        self.__ids_pause_check = wx.CheckBox(self, -1, u'Pause')
        self.__ids_pause_time_spin = wx.SpinCtrl(self, -1)
        self.__ids_pause_time_spin.SetRange(1, 120)
        self.__default_header_text = wx.TextCtrl(self, -1)
        self.__default_header_value_text = wx.TextCtrl(self, -1)
        # File Settings #
        self.__fuzzer_dir_list_text = wx.TextCtrl(self, -1)
        self.__fuzzer_file_list_text = wx.TextCtrl(self, -1)
        self.__fuzzer_ext_list_text = wx.TextCtrl(self, -1)
        self.__custom_db_dir_text = wx.TextCtrl(self, -1)
        self.__nikto_db_dir_text = wx.TextCtrl(self, -1)
        self.__fuzzer_dir_list_button = wx.Button(self, -1, u'...')
        self.__fuzzer_file_list_button = wx.Button(self, -1, u'...')
        self.__fuzzer_ext_list_button = wx.Button(self, -1, u'...')
        self.__custom_db_dir_button = wx.Button(self, -1, u'...')
        self.__nikto_db_dir_button = wx.Button(self, -1, u'...')
        # Portscan Module Settings #
        self.__nmap_check = wx.CheckBox(self, -1, u'Nmap installed')
        self.__nmap_location_text = wx.TextCtrl(self, -1)
        self.__nmap_location_button = wx.Button(self, -1, u'...')
        # Info module Settings #
        self.__live_id_text = wx.TextCtrl(self, -1)
        # Urlscan Module Settings #
        self.__scan_threads_spin = wx.SpinCtrl(self, -1)
        self.__scan_threads_spin.SetRange(1, 50)
        self.__scan_show_codes_text = wx.TextCtrl(self, -1)
        self.__use_db_nikto_check = wx.CheckBox(self, -1, u'Nikto Database')
        self.__use_db_custom_check = wx.CheckBox(self, -1, u'SCRT Database')
        # Spider Module Settings #
        self.__spider_threads_spin = wx.SpinCtrl(self, -1)
        self.__spider_threads_spin.SetRange(1, 50)
        self.__use_robots_check = wx.CheckBox(self, -1, u'Allow spider to (mis)use robots.txt')
        # Fuzer Module Settings #
        self.__fuzz_threads_spin = wx.SpinCtrl(self, -1)
        self.__fuzz_threads_spin.SetRange(1, 50)
        self.__fuzz_show_codes_text = wx.TextCtrl(self, -1)
        self.__fuzz_method_text = wx.TextCtrl(self, -1)
        # Buttons #
        self.__applyButton = wx.Button(self, wx.ID_APPLY, u'&Apply')
        self.__refreshButton = wx.Button(self, wx.ID_REFRESH, u'Refresh')
        self.__closeButton = wx.Button(self, wx.ID_CLOSE, u'&Close')
        self.__command_text = wx.StaticText(self, -1, u'')
        
        # Event Bindings #######################################
        self.Bind(wx.EVT_BUTTON, self.__onRefreshButton, id=self.__refreshButton.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onApplyButton, id=self.__applyButton.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onCloseButton, id=self.__closeButton.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onAuthCheck, id=self.__auth_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onProxyCheck, id=self.__proxy_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onProxyAuthCheck, id=self.__proxy_auth_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onIdsCheck, id=self.__ids_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onIdsRpCheck, id=self.__ids_rp_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onIdsPauseCheck, id=self.__ids_pause_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onNmapCheck, id=self.__nmap_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onNiktoCheck, id=self.__use_db_nikto_check.GetId())
        self.Bind(wx.EVT_CHECKBOX, self.__onCustomCheck, id=self.__use_db_custom_check.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onFuzzerDirListButton, id=self.__fuzzer_dir_list_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onFuzzerFileListButton, id=self.__fuzzer_file_list_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onFuzzerExtListButton, id=self.__fuzzer_ext_list_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onCustomDbDirButton, id=self.__custom_db_dir_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onNiktoDbDirButton, id=self.__nikto_db_dir_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onNmapLocationButton, id=self.__nmap_location_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onIdsRpListButton, id=self.__ids_rp_list_button.GetId())
        
        # Layout ###############################################
        httpGridSizer = wx.GridBagSizer()
        httpGridSizer.AddGrowableCol(0)
        
        httpGridSizer.Add(self.__ssl_check, (0, 0), (1, 2),  wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'User-Agent:'), (1, 0), (1, 1), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Socket Timeout:'), (1, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        httpGridSizer.Add(self.__user_agent_text, (2, 0), (1, 1),  wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__socket_timeout_spin, (2, 1), (1, 1),  wx.EXPAND | wx.RIGHT, 10)
        
        httpGridSizer.Add(wx.StaticText(self, -1, u'Default Header:'), (3, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__default_header_text, (4, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Default Header Value:'), (5, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__default_header_value_text, (6, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        
        httpGridSizer.Add(self.__auth_check, (7, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Username:'), (8, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__auth_username_text, (9, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Password:'), (10, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__auth_password_text, (11, 0), (1, 2), wx.EXPAND | wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        httpGridSizer.Add(self.__proxy_check, (12, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Host:'), (13, 0), (1, 1), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Port:'), (13, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        httpGridSizer.Add(self.__proxy_host_text, (14, 0), (1, 1), wx.EXPAND | wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__proxy_port_text, (14, 1), (1, 1), wx.EXPAND | wx.EXPAND | wx.RIGHT, 10)

        httpGridSizer.Add(self.__proxy_auth_check, (15, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Username:'), (16, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__proxy_username_text, (17, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Password:'), (18, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__proxy_password_text, (19, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        httpGridSizer.Add(self.__ids_check, (20, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__ids_rp_check, (21, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Proxy List:'), (22, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__ids_rp_list_text, (23, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        httpGridSizer.Add(self.__ids_rp_list_button, (23, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        httpGridSizer.Add(self.__ids_pause_check, (24, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(wx.StaticText(self, -1, u'Maximum Pause Time [seconds]:'), (25, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        httpGridSizer.Add(self.__ids_pause_time_spin, (26, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        
        fileGridSizer = wx.GridBagSizer()
        fileGridSizer.AddGrowableCol(0)
        
        fileGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer Dirs List:'), (0, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        fileGridSizer.Add(self.__fuzzer_dir_list_text, (1, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__fuzzer_dir_list_button, (1, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        fileGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer File List:'), (2, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        fileGridSizer.Add(self.__fuzzer_file_list_text, (3, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__fuzzer_file_list_button, (3, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        fileGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer Extension List:'), (4, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        fileGridSizer.Add(self.__fuzzer_ext_list_text, (5, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__fuzzer_ext_list_button, (5, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        fileGridSizer.Add(self.__use_db_nikto_check, (6, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        fileGridSizer.Add(self.__nikto_db_dir_text, (7, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__nikto_db_dir_button, (7, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        fileGridSizer.Add(self.__use_db_custom_check, (8, 0), (1, 2), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__custom_db_dir_text, (9, 0), (1, 1), wx.EXPAND | wx.LEFT, 10)
        fileGridSizer.Add(self.__custom_db_dir_button, (9, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        
        codesGridSizer = wx.GridBagSizer()
        codesGridSizer.AddGrowableCol(0)
        
        codesGridSizer.Add(wx.StaticText(self, -1, u'URL Scanner Show Codes:'), (0, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        codesGridSizer.Add(self.__scan_show_codes_text, (1, 0), (1, 2), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        codesGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer Show Codes:'), (2, 0), (1, 1), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        codesGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer Method:'), (2, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        codesGridSizer.Add(self.__fuzz_show_codes_text, (3, 0), (1, 1), wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        codesGridSizer.Add(self.__fuzz_method_text, (3, 1), (1, 1), wx.EXPAND | wx.RIGHT, 10)
        
        threadsGridSizer = wx.GridBagSizer()
        threadsGridSizer.AddGrowableCol(0)
        threadsGridSizer.AddGrowableCol(1)
        threadsGridSizer.AddGrowableCol(2)
        
        threadsGridSizer.Add(wx.StaticText(self, -1, u'Scanner Threads:'), (0, 0), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        threadsGridSizer.Add(wx.StaticText(self, -1, u'Fuzzer Threads:'), (0, 1), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        threadsGridSizer.Add(wx.StaticText(self, -1, u'Spider Threads:'), (0, 2), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        threadsGridSizer.Add(self.__scan_threads_spin, (1, 0), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        threadsGridSizer.Add(self.__fuzz_threads_spin, (1, 1), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        threadsGridSizer.Add(self.__spider_threads_spin, (1, 2), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        
        spiderGridSizer = wx.GridBagSizer()
        spiderGridSizer.AddGrowableCol(0)
        
        spiderGridSizer.Add(self.__use_robots_check, (0, 0), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        
        portscanGridSizer = wx.GridBagSizer()
        portscanGridSizer.AddGrowableCol(0)
        
        portscanGridSizer.Add(self.__nmap_check, (0, 0), (1, 2),  wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        portscanGridSizer.Add(self.__nmap_location_text, (1, 0), (1, 1),  wx.EXPAND | wx.LEFT, 10)
        portscanGridSizer.Add(self.__nmap_location_button, (1, 1), (1, 1),  wx.EXPAND | wx.RIGHT, 10)
        
        infoGridSizer = wx.GridBagSizer()
        infoGridSizer.AddGrowableCol(0)
        
        infoGridSizer.Add(wx.StaticText(self, -1, u'Live Search ID:'), (0, 0), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        infoGridSizer.Add(self.__live_id_text, (1, 0), (1, 1), wx.EXPAND | wx.RIGHT | wx.LEFT, 10)
        
        commandsSizer = wx.BoxSizer()
        commandsSizerGrid = wx.GridBagSizer()
        commandsSizerGrid.AddGrowableCol(1)
        commandsSizerGrid.Add(self.__command_text, (0, 0), (1, 1), wx.EXPAND | wx.ALIGN_LEFT | wx.ALL, 5)
        commandsSizerGrid.Add(wx.Panel(self, -1), (0, 1), (1, 1), wx.EXPAND | wx.ALL, 5)
        commandsSizerGrid.Add(self.__refreshButton, (0, 2), (1, 1), wx.ALIGN_RIGHT | wx.ALL, 5)
        commandsSizerGrid.Add(self.__closeButton, (0, 3), (1, 1), wx.ALIGN_RIGHT | wx.ALL, 5)
        commandsSizerGrid.Add(self.__applyButton, (0, 4), (1, 1), wx.ALIGN_RIGHT | wx.ALL, 5)
        commandsSizer.Add(commandsSizerGrid, 1, wx.EXPAND)
        
        rootSizer = wx.GridBagSizer()
        rootSizer.Add(wx.StaticText(self, -1, u'Configuration settings. Do not forget to confirm changes using \'Apply\' button!'), (0, 0), (1, 1), wx.EXPAND | wx.TOP | wx.LEFT | wx.RIGHT, 5)
        rootSizer.Add(wx.StaticLine(self, -1), (1, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(httpGridSizer, (2, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (3, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(fileGridSizer, (4, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (5, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(codesGridSizer, (6, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (7, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(threadsGridSizer, (8, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (9, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(spiderGridSizer, (10, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (11, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(portscanGridSizer, (12, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(wx.StaticLine(self, -1), (13, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        rootSizer.Add(infoGridSizer, (14, 0), (1, 1), wx.EXPAND)
        rootSizer.Add(commandsSizer, (15, 0), (1, 1), wx.EXPAND | wx.ALL, 10)
        rootSizer.AddGrowableCol(0)
        self.SetSizer(rootSizer)
        
        self.__load_config()
    
    def __onRefreshButton(self, event):
        self.__load_config()

    def __onApplyButton(self, event):
        self.__save_config()
        self.__parent.Close()

    def __onCloseButton(self, event):
        self.__parent.Close()

    def __onProxyCheck(self, event):
        if self.__proxy_check.GetValue():
            self.__proxy_host_text.Enable(True)
            self.__proxy_port_text.Enable(True)
        else:
            self.__proxy_host_text.Enable(False)
            self.__proxy_port_text.Enable(False)
    
    def __onProxyAuthCheck(self, event):
        if self.__proxy_auth_check.GetValue():
            self.__proxy_username_text.Enable(True)
            self.__proxy_password_text.Enable(True)
        else:
            self.__proxy_username_text.Enable(False)
            self.__proxy_password_text.Enable(False)
    
    def __onAuthCheck(self, event):
        if self.__auth_check.GetValue():
            self.__auth_username_text.Enable(True)
            self.__auth_password_text.Enable(True)
        else:
            self.__auth_username_text.Enable(False)
            self.__auth_password_text.Enable(False)
    
    def __onIdsCheck(self, event):
        if self.__ids_check.GetValue():
            self.__ids_rp_check.Enable(True)
            if self.__ids_rp_check.GetValue():
                self.__ids_rp_list_text.Enable(True)
                self.__ids_rp_list_button.Enable(True)
            else:
                self.__ids_rp_list_text.Enable(False)
            self.__ids_pause_check.Enable(True)
            if self.__ids_pause_check.GetValue():
                self.__ids_pause_time_spin.Enable(True)
            else:
                self.__ids_pause_time_spin.Enable(False)
        else:
            self.__ids_rp_check.Enable(False)
            self.__ids_rp_list_text.Enable(False)
            self.__ids_rp_list_button.Enable(False)
            self.__ids_pause_check.Enable(False)
            self.__ids_pause_time_spin.Enable(False)
    
    def __onIdsRpCheck(self, event):
        if self.__ids_rp_check.GetValue():
            self.__ids_rp_list_text.Enable(True)
            self.__ids_rp_list_button.Enable(True)
        else:
            self.__ids_rp_list_text.Enable(False)
            self.__ids_rp_list_button.Enable(False)
    
    def __onIdsPauseCheck(self, event):
        if self.__ids_pause_check.GetValue():
            self.__ids_pause_time_spin.Enable(True)
        else:
            self.__ids_pause_time_spin.Enable(False)
    
    def __onNiktoCheck(self, event):
        if self.__use_db_nikto_check.GetValue():
            self.__nikto_db_dir_text.Enable(True)
            self.__nikto_db_dir_button.Enable(True)
        else:
            self.__nikto_db_dir_text.Enable(False)
            self.__nikto_db_dir_button.Enable(False)
            
    def __onCustomCheck(self, event):
        if self.__use_db_custom_check.GetValue():
            self.__custom_db_dir_text.Enable(True)
            self.__custom_db_dir_button.Enable(True)
        else:
            self.__custom_db_dir_text.Enable(False)
            self.__custom_db_dir_button.Enable(False)
    
    def __onNmapCheck(self, event):
        if self.__nmap_check.GetValue():
            self.__nmap_location_text.Enable(True)
            self.__nmap_location_button.Enable(True)
        else:
            self.__nmap_location_text.Enable(False)
            self.__nmap_location_button.Enable(False)
    
    def __onFuzzerDirListButton(self, event):
        dlg = wx.FileDialog(self, "Choose File", style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.__fuzzer_dir_list_text.SetValue(dlg.GetPath())
        dlg.Destroy()

    def __onFuzzerFileListButton(self, event):
        dlg = wx.FileDialog(self, "Choose File", style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.__fuzzer_file_list_text.SetValue(dlg.GetPath())
        dlg.Destroy()
    
    def __onFuzzerExtListButton(self, event):
        dlg = wx.FileDialog(self, "Choose File", style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.__fuzzer_ext_list_text.SetValue(dlg.GetPath())
        dlg.Destroy()
    
    def __onCustomDbDirButton(self, event):
        dlg = wx.DirDialog(self, "Choose Directory", style=wx.DD_DIR_MUST_EXIST)
        if dlg.ShowModal() == wx.ID_OK:
            self.__custom_db_dir_text.SetValue(dlg.GetPath())
        dlg.Destroy()
    
    def __onNiktoDbDirButton(self, event):
        dlg = wx.DirDialog(self, "Choose Directory", style=wx.DD_DIR_MUST_EXIST)
        if dlg.ShowModal() == wx.ID_OK:
            self.__nikto_db_dir_text.SetValue(dlg.GetPath())
        dlg.Destroy()

    def __onNmapLocationButton(self, event):
        dlg = wx.FileDialog(self, "Choose File", style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.__nmap_location_text.SetValue(dlg.GetPath())
        dlg.Destroy()

    def __onIdsRpListButton(self, event):
        dlg = wx.FileDialog(self, "Choose File", style=wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.__ids_rp_list_text.SetValue(dlg.GetPath())
        dlg.Destroy()
    __onIdsRpListButton

    def __load_config(self):
        
        configParser = core_file.cfg_start_get()
        self.__fuzzer_dir_list_text.SetValue(core_file.cfg_get_fuzzer_dir_list(configParser))
        self.__fuzzer_file_list_text.SetValue(core_file.cfg_get_fuzzer_file_list(configParser))
        self.__fuzzer_ext_list_text.SetValue(core_file.cfg_get_fuzzer_ext_list(configParser))
        self.__nikto_db_dir_text.SetValue(core_file.cfg_get_nikto_db_dir(configParser))
        self.__custom_db_dir_text.SetValue(core_file.cfg_get_custom_db_dir(configParser))
        self.__proxy_check.SetValue(core_file.cfg_get_proxy(configParser))
        self.__proxy_auth_check.SetValue(core_file.cfg_get_proxy_auth(configParser))
        self.__proxy_host_text.SetValue(core_file.cfg_get_proxy_host(configParser))
        self.__proxy_port_text.SetValue(unicode(core_file.cfg_get_proxy_port(configParser)))
        self.__proxy_username_text.SetValue(core_file.cfg_get_proxy_username(configParser))
        self.__proxy_password_text.SetValue(core_file.cfg_get_proxy_password(configParser))
        self.__socket_timeout_spin.SetValue(core_file.cfg_get_socket_timeout(configParser))
        self.__ids_check.SetValue(core_file.cfg_get_ids(configParser))
        self.__ids_rp_check.SetValue(core_file.cfg_get_ids_rp(configParser))
        self.__ids_rp_list_text.SetValue(core_file.cfg_get_ids_rp_list(configParser))
        self.__ids_pause_check.SetValue(core_file.cfg_get_ids_pause(configParser))
        self.__ids_pause_time_spin.SetValue(core_file.cfg_get_ids_pause_time(configParser))
        self.__auth_check.SetValue(core_file.cfg_get_auth(configParser))
        self.__ssl_check.SetValue(core_file.cfg_get_ssl(configParser))
        self.__auth_username_text.SetValue(core_file.cfg_get_auth_username(configParser))
        self.__auth_password_text.SetValue(core_file.cfg_get_auth_password(configParser))
        self.__user_agent_text.SetValue(core_file.cfg_get_user_agent(configParser))
        self.__nmap_check.SetValue(core_file.cfg_get_nmap(configParser))
        self.__nmap_location_text.SetValue(core_file.cfg_get_nmap_location(configParser))
        self.__live_id_text.SetValue(core_file.cfg_get_live_id(configParser))
        self.__use_db_nikto_check.SetValue(core_file.cfg_get_use_db_nikto(configParser))
        self.__use_db_custom_check.SetValue(core_file.cfg_get_use_db_custom(configParser))
        self.__scan_show_codes_text.SetValue(core_file.cfg_get_scan_show_codes(configParser))
        self.__scan_threads_spin.SetValue(core_file.cfg_get_scan_threads(configParser))
        self.__fuzz_show_codes_text.SetValue(core_file.cfg_get_fuzz_show_codes(configParser))
        self.__fuzz_threads_spin.SetValue(core_file.cfg_get_fuzz_threads(configParser))
        self.__spider_threads_spin.SetValue(core_file.cfg_get_spider_threads(configParser))
        self.__fuzz_method_text.SetValue(core_file.cfg_get_fuzz_method(configParser))
        self.__use_robots_check.SetValue(core_file.cfg_get_use_robots(configParser))
        self.__default_header_text.SetValue(core_file.cfg_get_default_header(configParser))
        self.__default_header_value_text.SetValue(core_file.cfg_get_default_header_value(configParser))
        core_file.cfg_end_get(configParser)
        
        if self.__proxy_check.GetValue():
            self.__proxy_host_text.Enable(True)
            self.__proxy_port_text.Enable(True)
        else:
            self.__proxy_host_text.Enable(False)
            self.__proxy_port_text.Enable(False)
    
        if self.__proxy_auth_check.GetValue():
            self.__proxy_username_text.Enable(True)
            self.__proxy_password_text.Enable(True)
        else:
            self.__proxy_username_text.Enable(False)
            self.__proxy_password_text.Enable(False)

        if self.__auth_check.GetValue():
            self.__auth_username_text.Enable(True)
            self.__auth_password_text.Enable(True)
        else:
            self.__auth_username_text.Enable(False)
            self.__auth_password_text.Enable(False)
    
        if self.__ids_check.GetValue():
            self.__ids_rp_check.Enable(True)
            self.__ids_rp_list_text.Enable(True)
            self.__ids_rp_list_button.Enable(True)
            self.__ids_pause_check.Enable(True)
            self.__ids_pause_time_spin.Enable(True)
        else:
            self.__ids_rp_check.Enable(False)
            self.__ids_rp_list_text.Enable(False)
            self.__ids_rp_list_button.Enable(False)
            self.__ids_pause_check.Enable(False)
            self.__ids_pause_time_spin.Enable(False)

        if self.__nmap_check.GetValue():
            self.__nmap_location_text.Enable(True)
            self.__nmap_location_button.Enable(True)
        else:
            self.__nmap_location_text.Enable(False)
            self.__nmap_location_button.Enable(False)

        if self.__use_db_nikto_check.GetValue():
            self.__nikto_db_dir_text.Enable(True)
            self.__nikto_db_dir_button.Enable(True)
        else:
            self.__nikto_db_dir_text.Enable(False)
            self.__nikto_db_dir_button.Enable(False)
        
        if self.__use_db_custom_check.GetValue():
            self.__custom_db_dir_text.Enable(True)
            self.__custom_db_dir_button.Enable(True)
        else:
            self.__custom_db_dir_text.Enable(False)
            self.__custom_db_dir_button.Enable(False)


    def __save_config(self):
        
        configParser = core_file.cfg_start_set()
        
        core_file.cfg_set_fuzzer_dir_list(configParser, self.__fuzzer_dir_list_text.GetValue())
        core_file.cfg_set_fuzzer_file_list(configParser, self.__fuzzer_file_list_text.GetValue())
        core_file.cfg_set_fuzzer_ext_list(configParser, self.__fuzzer_ext_list_text.GetValue())
        core_file.cfg_set_nikto_db_dir(configParser, self.__nikto_db_dir_text.GetValue())
        core_file.cfg_set_custom_db_dir(configParser, self.__custom_db_dir_text.GetValue())
        core_file.cfg_set_proxy(configParser, self.__proxy_check.GetValue())
        core_file.cfg_set_proxy_auth(configParser, self.__proxy_auth_check.GetValue())
        core_file.cfg_set_proxy_host(configParser, self.__proxy_host_text.GetValue())
        core_file.cfg_set_default_header(configParser, self.__default_header_text.GetValue())
        core_file.cfg_set_default_header_value(configParser, self.__default_header_value_text.GetValue())
        
        if self.__proxy_port_text.GetValue() != '' and core_utilities.check_port_string(self.__proxy_port_text.GetValue()):
            core_file.cfg_set_proxy_port(configParser, self.__proxy_port_text.GetValue())
        else:
            core_file.cfg_set_proxy_port(configParser, u'0')
        
        core_file.cfg_set_proxy_username(configParser, self.__proxy_username_text.GetValue())
        core_file.cfg_set_proxy_password(configParser, self.__proxy_password_text.GetValue())
        core_file.cfg_set_socket_timeout(configParser, self.__socket_timeout_spin.GetValue())
        core_file.cfg_set_ids(configParser, self.__ids_check.GetValue())
        core_file.cfg_set_ids_rp(configParser, self.__ids_rp_check.GetValue())
        core_file.cfg_set_ids_rp_list(configParser, self.__ids_rp_list_text.GetValue())
        core_file.cfg_set_ids_pause(configParser, self.__ids_pause_check.GetValue())
        core_file.cfg_set_ids_pause_time(configParser, self.__ids_pause_time_spin.GetValue())
        core_file.cfg_set_auth(configParser, self.__auth_check.GetValue())
        core_file.cfg_set_ssl(configParser, self.__ssl_check.GetValue())
        core_file.cfg_set_auth_username(configParser, self.__auth_username_text.GetValue())
        core_file.cfg_set_auth_password(configParser, self.__auth_password_text.GetValue())
        core_file.cfg_set_user_agent(configParser, self.__user_agent_text.GetValue())
        core_file.cfg_set_nmap(configParser, self.__nmap_check.GetValue())
        core_file.cfg_set_nmap_location(configParser, self.__nmap_location_text.GetValue())
        core_file.cfg_set_live_id(configParser, self.__live_id_text.GetValue())
        core_file.cfg_set_use_db_nikto(configParser, self.__use_db_nikto_check.GetValue())
        core_file.cfg_set_use_db_custom(configParser, self.__use_db_custom_check.GetValue())
        core_file.cfg_set_scan_show_codes(configParser, self.__scan_show_codes_text.GetValue())
        core_file.cfg_set_scan_threads(configParser, self.__scan_threads_spin.GetValue())
        core_file.cfg_set_fuzz_show_codes(configParser, self.__fuzz_show_codes_text.GetValue())
        core_file.cfg_set_fuzz_threads(configParser, self.__fuzz_threads_spin.GetValue())
        core_file.cfg_set_spider_threads(configParser, self.__spider_threads_spin.GetValue())
        core_file.cfg_set_fuzz_method(configParser, self.__fuzz_method_text.GetValue())
        core_file.cfg_set_use_robots(configParser, self.__use_robots_check.GetValue())
        core_file.cfg_end_set(configParser)


## ################################################################# ##
## CLASS: ExportDialog
## ################################################################# ##
## This class displays the report exporting dialog
## ################################################################# ##
class ExportDialog(wx.Dialog):
    
    def __init__(self, parent, results):
        wx.Dialog.__init__(self, parent, -1, u'Export Report...', size=(450, 240))
        expPanel = Export_Panel(self, results)
        rootSizer = wx.BoxSizer()
        rootSizer.Add(expPanel, 1, wx.EXPAND)
        self.SetSizer(rootSizer)

## ################################################################# ##
## CLASS: Export_Panel
## ################################################################# ##
## This class provides a GUI for exporting reports
## ################################################################# ##
class Export_Panel(wx.Panel):
    
    def __init__(self, parent, results):
        
        wx.Panel.__init__(self, parent)
        self.__parent = parent
        self.__results = results
        
        formats = EXPORT_FORMATS
        
        # Widgets ##############################################
        self.__openPortscan_check = wx.CheckBox(self, -1, u'Port Scanner')
        self.__openPortscan_check.SetValue(True)
        self.__info_check = wx.CheckBox(self, -1, u'Info')
        self.__info_check.SetValue(True)
        self.__spider_check = wx.CheckBox(self, -1, u'Spider')
        self.__spider_check.SetValue(True)
        self.__urlscan_check = wx.CheckBox(self, -1, u'URL Scanner')
        self.__urlscan_check.SetValue(True)
        self.__fuzz_check = wx.CheckBox(self, -1, u'Fuzzer')
        self.__fuzz_check.SetValue(True)
        self.__file_text = wx.TextCtrl(self, -1)
        self.__file_button = wx.Button(self, wx.ID_OPEN, u'&Open')
        self.__format_combo = wx.ComboBox(self, -1, style=wx.CB_READONLY, choices=formats)
        self.__format_combo.SetValue(formats[0])
        self.__apply_button = wx.Button(self, wx.ID_APPLY, u'&Apply')
        self.__close_button = wx.Button(self, wx.ID_CLOSE, u'&Close')
        self.__command_text = wx.StaticText(self, -1, u'')
        
        # Event Bindings ##############################################
        self.Bind(wx.EVT_BUTTON, self.__onCloseButton, id=self.__close_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onBrowseButton, id=self.__file_button.GetId())
        self.Bind(wx.EVT_BUTTON, self.__onApplyButton, id=self.__apply_button.GetId())
        
        # Layout Management ##############################################
        rootSizer =  wx.BoxSizer(orient=wx.VERTICAL)
        boxesGridSizer = wx.GridBagSizer()
        boxesGridSizer.Add(wx.StaticText(self, -1, u'Export Results:'), (0, 0), (1, 5), wx.EXPAND | wx.TOP, 5)
        boxesGridSizer.Add(self.__openPortscan_check, (1, 0), (1, 1), wx.EXPAND | wx.ALL, 5)
        boxesGridSizer.Add(self.__info_check, (1, 1), (1, 1), wx.EXPAND | wx.ALL, 5)
        boxesGridSizer.Add(self.__spider_check, (1, 2), (1, 1), wx.EXPAND | wx.ALL, 5)
        boxesGridSizer.Add(self.__urlscan_check, (1, 3), (1, 1), wx.EXPAND | wx.ALL, 5)
        boxesGridSizer.Add(self.__fuzz_check, (1, 4), (1, 1), wx.EXPAND | wx.ALL, 5)
        boxesGridSizer.AddGrowableCol(0)
        boxesGridSizer.AddGrowableCol(1)
        boxesGridSizer.AddGrowableCol(2)
        boxesGridSizer.AddGrowableCol(3)
        boxesGridSizer.AddGrowableCol(4)
        fileGridSizer = wx.GridBagSizer()
        fileGridSizer.Add(wx.StaticText(self, -1, u'Output File:'), (0, 0), (1, 2), wx.EXPAND)
        fileGridSizer.Add(self.__file_text, (1, 0), (1, 1), wx.EXPAND)
        fileGridSizer.Add(self.__file_button, (1, 1), (1, 1))
        fileGridSizer.AddGrowableCol(0)
        formatGridSizer = wx.GridBagSizer()
        formatGridSizer.Add(wx.StaticText(self, -1, u'Output File Format:'), (0, 0), (1, 2), wx.EXPAND)
        formatGridSizer.Add(self.__format_combo, (1, 0), (1, 2), wx.EXPAND)
        formatGridSizer.AddGrowableCol(0)
        buttonGridSizer = wx.GridBagSizer()
        buttonGridSizer.Add(self.__command_text, (0, 0), (1, 1), wx.ALIGN_CENTER_VERTICAL)
        buttonGridSizer.Add(self.__close_button, (0, 1), (1, 1), wx.EXPAND)
        buttonGridSizer.Add(self.__apply_button, (0, 2), (1, 1), wx.EXPAND)
        buttonGridSizer.AddGrowableCol(0)
        rootSizer.Add(boxesGridSizer, 0, wx.EXPAND | wx.TOP | wx.RIGHT | wx.LEFT, 3)
        rootSizer.Add(fileGridSizer, 0, wx.EXPAND | wx.TOP | wx.RIGHT | wx.LEFT, 3)
        rootSizer.Add(formatGridSizer, 0, wx.EXPAND | wx.TOP | wx.RIGHT | wx.LEFT, 3)
        rootSizer.Add(buttonGridSizer, 0, wx.EXPAND | wx.TOP | wx.LEFT, 10)
        self.SetSizer(rootSizer)
    
    
    def __onCloseButton(self, event):
        self.__parent.Close()
        
    def __onBrowseButton(self, event):
        dlg = wx.FileDialog(self, "Output File", style=wx.SAVE)
        if dlg.ShowModal() == wx.ID_OK:
            self.__file_text.SetValue(dlg.GetPath())
        dlg.Destroy()
        
    def __onApplyButton(self, event):
        
        file = self.__file_text.GetValue()
        if not core_utilities.check_save_file_path(file):
            self.__command_text.SetLabel(u'Invalid Filename!')
        else:
            
            if self.__results[MODULE_INFO] and self.__info_check.GetValue():
                info = self.__results[MODULE_INFO]
            else:
                info = None
            
            if self.__results[MODULE_PSCAN] and self.__openPortscan_check.GetValue():
                pscan = self.__results[MODULE_PSCAN]
            else:
                pscan = None
            
            if self.__results[MODULE_USCAN] and self.__urlscan_check.GetValue():
                uscan = self.__results[MODULE_USCAN]
            else:
                uscan = None
            
            if self.__results[MODULE_FUZZ] and self.__fuzz_check.GetValue():
                fuzz = self.__results[MODULE_FUZZ]
            else:
                fuzz = None
            
            if self.__results[MODULE_SPIDER] and self.__spider_check.GetValue():
                spider = self.__results[MODULE_SPIDER]
            else:
                spider = None
            
            success = export.exp_report(file, self.__format_combo.GetValue(), info, pscan, uscan, fuzz, spider)
            
            if success:
                self.__parent.Close()
            else:
                self.__command_text.SetLabel(u'Export Failed')


## ################################################################# ##
## CLASS: ImportDialog
## ################################################################# ##
## This class displays the import dialog used by URL scanner and
## fuzzer panels to import results from other modules
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
