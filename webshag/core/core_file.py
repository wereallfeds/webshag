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
## last mod: 2008-12-31

import re
import codecs
from ConfigParser import SafeConfigParser
import os.path
import core_error, core_utilities

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

# This variable is overwritten by configuration script
CFG_FILE = 'P:/webshag/dev/1.1/config/webshag.conf'

FILE_ENCODING = u'utf-8'
CFG_SECTION_FILE = u'core_file'
CFG_SECTION_HTTP = u'core_http'
CFG_SECTION_INFO = u'module_info'
CFG_SECTION_PORTSCAN = u'module_portscan'
CFG_SECTION_URLSCAN = u'module_urlscan'
CFG_SECTION_FUZZ = u'module_fuzz'
CFG_SECTION_SPIDER = u'module_spider'
HTTP_CODE_REGEXP = re.compile(r'^[0-9]{3}$')
NIKTO_DB_VARIABLES = u'db_variables'
NIKTO_DB_TESTS = u'db_tests'
NIKTO_DB_ENCODING = u'iso-8859-1'
CUSTOM_DB_TESTS = u'custom_tests.db'
CUSTOM_DB_BANNERS = u'banners.db'
CUSTOM_DB_ENCODING = u'utf-8'
FUZZ_DATABASE_COMMENT = u'#'
IDS_DATABASE_COMMENT = u'#'
NIKTO_JUNK_REGEXP = re.compile(r'(?P<match>JUNK\((?P<size>\d+)\))')

## ################################################################# ##
## CONFIG FUNCTIONS
## ################################################################# ##
## These functions are all relative to config file loading/saving
## parameters. All the modules have to go through one of these
## functions to read or write a value stored in config file.
## Actually, every config parameter (e.g test) corresponds to two
## functions defined below: 'cfg_get_test' (read) and 'cfg_set_test'
## (write). In addition to these, four other functions are used to
## initiate and end reading/writing of config file (for optimization
## purposes). This choice may seem a bit comlicated but is driven
## by the idea of totally decoupling modules from config file
## organization and format. This way, changing config file format or
## splitting it in several files will have no influence on modules.
## ################################################################# ##

def cfg_start_get():
    configParser = SafeConfigParser()
    configParser.readfp(codecs.open(CFG_FILE, u'r', FILE_ENCODING))
    return configParser

## ################################################################# ##

def cfg_end_get(configParser):
    del configParser

## ################################################################# ##

def cfg_start_set():
    configParser = SafeConfigParser()
    file = codecs.open(CFG_FILE, u'r', FILE_ENCODING)
    configParser.readfp(file)
    file.close()
    return configParser

## ################################################################# ##

def cfg_end_set(configParser):
    file = codecs.open(CFG_FILE, u'w', FILE_ENCODING)
    configParser.write(file)
    file.close()

## ################################################################# ##

def cfg_get_fuzzer_dir_list(configParser):
    return configParser.get(CFG_SECTION_FILE, u'fuzzer_dir_list')

## ################################################################# ##

def cfg_get_fuzzer_ext_list(configParser):
    return configParser.get(CFG_SECTION_FILE, u'fuzzer_ext_list')

## ################################################################# ##

def cfg_get_fuzzer_file_list(configParser):
    return configParser.get(CFG_SECTION_FILE, u'fuzzer_file_list')

## ################################################################# ##

def cfg_get_nikto_db_dir(configParser):
    return configParser.get(CFG_SECTION_FILE, u'nikto_db_dir')

## ################################################################# ##

def cfg_get_custom_db_dir(configParser):
    return configParser.get(CFG_SECTION_FILE, u'custom_db_dir')

## ################################################################# ##

def cfg_get_proxy(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'proxy')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'proxy\' parameter')
    
## ################################################################# ##

def cfg_get_proxy_auth(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'proxy_auth')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'proxy_auth\' parameter')
    
## ################################################################# ##

def cfg_get_proxy_host(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'proxy_host')

## ################################################################# ##

def cfg_get_proxy_port(configParser):
    try:
        return configParser.getint(CFG_SECTION_HTTP, u'proxy_port')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'proxy_port\' parameter')

## ################################################################# ##
    
def cfg_get_proxy_username(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'proxy_username')

## ################################################################# ##
    
def cfg_get_proxy_password(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'proxy_password')

## ################################################################# ##

def cfg_get_socket_timeout(configParser):
    try:
        return configParser.getint(CFG_SECTION_HTTP, u'socket_timeout')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'socket_timeout\' parameter')

## ################################################################# ##
    
def cfg_get_ids(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'ids')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'ids\' parameter')
    
## ################################################################# ##
    
def cfg_get_ids_rp(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'ids_rp')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'ids_rp\' parameter')
    
## ################################################################# ##
    
def cfg_get_ids_rp_list(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'ids_rp_list')

## ################################################################# ##
    
def cfg_get_ids_pause(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'ids_pause')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'ids_pause\' parameter')
    
## ################################################################# ##
    
def cfg_get_ids_pause_time(configParser):
    try:
        return configParser.getint(CFG_SECTION_HTTP, u'ids_pause_time')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'ids_pause_time\' parameter')

## ################################################################# ##

def cfg_get_auth(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'auth')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'auth\' parameter')
    
## ################################################################# ##
    
def cfg_get_ssl(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_HTTP, u'ssl')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'ssl\' parameter')
    
## ################################################################# ##

def cfg_get_auth_username(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'auth_username')

## ################################################################# ##

def cfg_get_auth_password(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'auth_password')

## ################################################################# ##
    
def cfg_get_user_agent(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'user_agent')

## ################################################################# ##

def cfg_get_nmap(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_PORTSCAN, u'nmap')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'nmap\' parameter')

## ################################################################# ##
    
def cfg_get_nmap_location(configParser):
    return configParser.get(CFG_SECTION_PORTSCAN, u'nmap_location')

## ################################################################# ##

def cfg_get_live_id(configParser):
    return configParser.get(CFG_SECTION_INFO, u'live_id')

## ################################################################# ##

def cfg_get_use_db_nikto(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_URLSCAN, u'use_db_nikto')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'use_db_nikto\' parameter')
    
## ################################################################# ##

def cfg_get_use_db_custom(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_URLSCAN, u'use_db_custom')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'use_db_custom\' parameter')
## ################################################################# ##

def cfg_get_scan_show_codes(configParser):
    return configParser.get(CFG_SECTION_URLSCAN, u'scan_show_codes')

## ################################################################# ##
    
def cfg_get_scan_threads(configParser):
    try:
        return configParser.getint(CFG_SECTION_URLSCAN, u'scan_threads')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'scan_threads\' parameter')

## ################################################################# ##
    
def cfg_get_fuzz_show_codes(configParser):
    return configParser.get(CFG_SECTION_FUZZ, u'fuzz_show_codes')

## ################################################################# ##
    
def cfg_get_fuzz_method(configParser):
    return configParser.get(CFG_SECTION_FUZZ, u'fuzz_method')

## ################################################################# ##

def cfg_get_fuzz_threads(configParser):
    try:
        return configParser.getint(CFG_SECTION_FUZZ, u'fuzz_threads')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'fuzz_threads\' parameter')

## ################################################################# ##
    
def cfg_get_spider_threads(configParser):
    try:
        return configParser.getint(CFG_SECTION_SPIDER, u'spider_threads')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'spider_threads\' parameter')

## ################################################################# ##

def cfg_get_use_robots(configParser):
    try:
        return configParser.getboolean(CFG_SECTION_SPIDER, u'use_robots')
    except ValueError:
        raise core_error.Config_Error('Invalid configuration value for \'use_robots\' parameter')
    
## ################################################################# ##

def cfg_get_default_header(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'default_header')

## ################################################################# ##

def cfg_get_default_header_value(configParser):
    return configParser.get(CFG_SECTION_HTTP, u'default_header_value')
    
## ################################################################# ##

def cfg_set_fuzzer_dir_list(configParser, value):
    if configParser.has_section(CFG_SECTION_FILE):
        configParser.set(CFG_SECTION_FILE, u'fuzzer_dir_list', value)
    else:
        configParser.add_section(CFG_SECTION_FILE)
        configParser.set(CFG_SECTION_FILE, u'fuzzer_dir_list', value)

## ################################################################# ##

def cfg_set_fuzzer_file_list(configParser, value):
    if configParser.has_section(CFG_SECTION_FILE):
        configParser.set(CFG_SECTION_FILE, u'fuzzer_file_list', value)
    else:
        configParser.add_section(CFG_SECTION_FILE)
        configParser.set(CFG_SECTION_FILE, u'fuzzer_file_list', value)
        
## ################################################################# ##

def cfg_set_fuzzer_ext_list(configParser, value):
    if configParser.has_section(CFG_SECTION_FILE):
        configParser.set(CFG_SECTION_FILE, u'fuzzer_ext_list', value)
    else:
        configParser.add_section(CFG_SECTION_FILE)
        configParser.set(CFG_SECTION_FILE, u'fuzzer_ext_list', value)

## ################################################################# ##        

def cfg_set_nikto_db_dir(configParser, value):
    if configParser.has_section(CFG_SECTION_FILE):
        configParser.set(CFG_SECTION_FILE, u'nikto_db_dir', value)
    else:
        configParser.add_section(CFG_SECTION_FILE)
        configParser.set(CFG_SECTION_FILE, u'nikto_db_dir', value)

## ################################################################# ##

def cfg_set_custom_db_dir(configParser, value):
    if configParser.has_section(CFG_SECTION_FILE):
        configParser.set(CFG_SECTION_FILE, u'custom_db_dir', value)
    else:
        configParser.add_section(CFG_SECTION_FILE)
        configParser.set(CFG_SECTION_FILE, u'custom_db_dir', value)

## ################################################################# ##

def cfg_set_proxy(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'proxy', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'proxy', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'proxy', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'proxy', u'False')
            
## ################################################################# ##

def cfg_set_proxy_auth(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'proxy_auth', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'proxy_auth', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'proxy_auth', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'proxy_auth', u'False')

## ################################################################# ##

def cfg_set_proxy_host(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'proxy_host', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'proxy_host', value)

## ################################################################# ##

def cfg_set_proxy_username(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'proxy_username', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'proxy_username', value)

## ################################################################# ##

def cfg_set_proxy_password(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'proxy_password', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'proxy_password', value)

## ################################################################# ##

def cfg_set_proxy_port(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'proxy_port', str(value))
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'proxy_port', str(value))

## ################################################################# ##

def cfg_set_socket_timeout(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'socket_timeout', str(value))
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'socket_timeout', str(value))

## ################################################################# ##

def cfg_set_ids(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids', u'False')

## ################################################################# ##

def cfg_set_ids_rp(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids_rp', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids_rp', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids_rp', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids_rp', u'False')
            
## ################################################################# ##

def cfg_set_ids_rp_list(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'ids_rp_list', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'ids_rp_list', value)
        
## ################################################################# ##

def cfg_set_ids_pause(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids_pause', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids_pause', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ids_pause', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ids_pause', u'False')

## ################################################################# ##

def cfg_set_ids_pause_time(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'ids_pause_time', str(value))
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'ids_pause_time', str(value))

## ################################################################# ##

def cfg_set_auth(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'auth', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'auth', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'auth', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'auth', u'False')

## ################################################################# ##

def cfg_set_ssl(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ssl', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ssl', u'False')
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        if value:
            configParser.set(CFG_SECTION_HTTP, u'ssl', u'True')
        else:
            configParser.set(CFG_SECTION_HTTP, u'ssl', u'False')
            
## ################################################################# ##

def cfg_set_auth_username(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'auth_username', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'auth_username', value)

## ################################################################# ##

def cfg_set_auth_password(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'auth_password', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'auth_password', value)

## ################################################################# ##

def cfg_set_user_agent(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'user_agent', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'user_agent', value)

## ################################################################# ##
    
def cfg_set_nmap(configParser, value):
    if configParser.has_section(CFG_SECTION_PORTSCAN):
        if value:
            configParser.set(CFG_SECTION_PORTSCAN, u'nmap', u'True')
        else:
            configParser.set(CFG_SECTION_PORTSCAN, u'nmap', u'False')
    else:
        configParser.add_section(CFG_SECTION_PORTSCAN)
        if value:
            configParser.set(CFG_SECTION_PORTSCAN, u'nmap', u'True')
        else:
            configParser.set(CFG_SECTION_PORTSCAN, u'nmap', u'False')

## ################################################################# ##

def cfg_set_nmap_location(configParser, value):
    if configParser.has_section(CFG_SECTION_PORTSCAN):
        configParser.set(CFG_SECTION_PORTSCAN, u'nmap_location', value)
    else:
        configParser.add_section(CFG_SECTION_PORTSCAN)
        configParser.set(CFG_SECTION_PORTSCAN, u'nmap_location', value)

## ################################################################# ##

def cfg_set_live_id(configParser, value):
    if configParser.has_section(CFG_SECTION_PORTSCAN):
        configParser.set(CFG_SECTION_INFO, u'live_id', value)
    else:
        configParser.add_section(CFG_SECTION_PORTSCAN)
        configParser.set(CFG_SECTION_INFO, u'live_id', value)

## ################################################################# ##
    
def cfg_set_use_db_nikto(configParser, value):
    if configParser.has_section(CFG_SECTION_URLSCAN):
        if value:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_nikto', u'True')
        else:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_nikto', u'False')
    else:
        configParser.add_section(CFG_SECTION_URLSCAN)
        if value:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_nikto', u'True')
        else:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_nikto', u'False')

## ################################################################# ##
    
def cfg_set_use_db_custom(configParser, value):
    if configParser.has_section(CFG_SECTION_URLSCAN):
        if value:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_custom', u'True')
        else:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_custom', u'False')
    else:
        configParser.add_section(CFG_SECTION_URLSCAN)
        if value:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_custom', u'True')
        else:
            configParser.set(CFG_SECTION_URLSCAN, u'use_db_custom', u'False')

## ################################################################# ##

def cfg_set_scan_show_codes(configParser, value):
    if configParser.has_section(CFG_SECTION_URLSCAN):
        configParser.set(CFG_SECTION_URLSCAN , u'scan_show_codes', value)
    else:
        configParser.add_section(CFG_SECTION_URLSCAN)
        configParser.set(CFG_SECTION_URLSCAN , u'scan_show_codes', value)

## ################################################################# ##

def cfg_set_scan_threads(configParser, value):
    if configParser.has_section(CFG_SECTION_URLSCAN):
        configParser.set(CFG_SECTION_URLSCAN , u'scan_threads', str(value))
    else:
        configParser.add_section(CFG_SECTION_URLSCAN)
        configParser.set(CFG_SECTION_URLSCAN , u'scan_threads', str(value))

## ################################################################# ##

def cfg_set_fuzz_show_codes(configParser, value):
    if configParser.has_section(CFG_SECTION_FUZZ):
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_show_codes', value)
    else:
        configParser.add_section(CFG_SECTION_FUZZ)
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_show_codes', value)

## ################################################################# ##

def cfg_set_fuzz_method(configParser, value):
    if configParser.has_section(CFG_SECTION_FUZZ):
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_method', value)
    else:
        configParser.add_section(CFG_SECTION_FUZZ)
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_method', value)

## ################################################################# ##

def cfg_set_fuzz_threads(configParser, value):
    if configParser.has_section(CFG_SECTION_FUZZ):
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_threads', str(value))
    else:
        configParser.add_section(CFG_SECTION_FUZZ)
        configParser.set(CFG_SECTION_FUZZ , u'fuzz_threads', str(value))

## ################################################################# ##

def cfg_set_spider_threads(configParser, value):
    if configParser.has_section(CFG_SECTION_SPIDER):
        configParser.set(CFG_SECTION_SPIDER , u'spider_threads', str(value))
    else:
        configParser.add_section(CFG_SECTION_SPIDER)
        configParser.set(CFG_SECTION_SPIDER , u'spider_threads', str(value))

## ################################################################# ##

def cfg_set_use_robots(configParser, value):
    if configParser.has_section(CFG_SECTION_SPIDER):
        if value:
            configParser.set(CFG_SECTION_SPIDER, u'use_robots', u'True')
        else:
            configParser.set(CFG_SECTION_SPIDER, u'use_robots', u'False')
    else:
        configParser.add_section(CFG_SECTION_SPIDER)
        if value:
            configParser.set(CFG_SECTION_SPIDER, u'use_robots', u'True')
        else:
            configParser.set(CFG_SECTION_SPIDER, u'use_robots', u'False')

## ################################################################# ##

def cfg_set_default_header(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'default_header', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'default_header', value)

## ################################################################# ##

def cfg_set_default_header_value(configParser, value):
    if configParser.has_section(CFG_SECTION_HTTP):
        configParser.set(CFG_SECTION_HTTP, u'default_header_value', value)
    else:
        configParser.add_section(CFG_SECTION_HTTP)
        configParser.set(CFG_SECTION_HTTP, u'default_header_value', value)
    

## ################################################################# ##
## URL DATABASE FUNCTIONS
## ################################################################# ##
## These functions are relative to URL databases (Nikto and custom).
## ################################################################# ##

def db_load_nikto_tests():
    
    nikto_variables = {}
    nikto_tests = []
    
    # load config parameters #
    nikto_db_dir = cfg_get_nikto_db_dir(cfg_start_get())
    if not core_utilities.check_dir_path(nikto_db_dir):
        raise core_error.Config_Error(u'Invalid configuration value for \'nikto_db_dir\' parameter')
    
    elif not os.path.exists(nikto_db_dir + u'/' +  NIKTO_DB_VARIABLES):
        raise core_error.ConfigError(u'Inexistent file: ' + nikto_db_dir + u'/' +  NIKTO_DB_VARIABLES)
    
    elif not os.path.exists(nikto_db_dir + u'/' +  NIKTO_DB_TESTS):
        raise core_error.Config_Error(u'Inexistent file: ' + nikto_db_dir + u'/' +  NIKTO_DB_TESTS)
    
    else:
        
        fileHandle = codecs.open(nikto_db_dir + u'/' +  NIKTO_DB_VARIABLES, 'r', NIKTO_DB_ENCODING)
        lines = fileHandle.readlines()
        fileHandle.close()
        
        for line in lines:
            line = line.strip()
            
            if len(line) > 0 and line[0] == u'@':
                variable, sep, values_str = line.partition(u'=')
                values = values_str.split()
                nikto_variables[variable] = values
            else:
                continue
        
        fileHandle = codecs.open(nikto_db_dir + u'/' +  NIKTO_DB_TESTS, 'r', NIKTO_DB_ENCODING)
        lines = fileHandle.readlines()
        fileHandle.close()
        
        for line in lines:
            line = line.strip()
    
            
            # skip comments or blank lines #
            if len(line) == 0 or line[0] == u'#':
                continue
            
            else:
                
                # replace the JUNK(X) entries in Nikto database by actual junk
                junk_matches = NIKTO_JUNK_REGEXP.findall(line)
                if len(junk_matches) > 0:
                    for match in junk_matches:
                        line = line.replace(match[0], core_utilities.random_string(int(match[1])))
                else:
                    pass
                
                
                # the code below 'extends' the test by replacing the nikto_variables by their possible values.
                # It can support an arbitrary number of variables per line. A single test line containing 
                # X variables of Y possible values each will be 'extended' to produce Y^X test lines.
                #
                # @VAR1     =   /value_11/ /value_21/
                # @VAR2     =   /value_12/ /value_22/
                # LINE      =   "000000","0","x","@VAR1no_mather_what@VAR2","GET","200","","","","","example","",""
                #
                # ==> "000000","0","x","/value_11/no_mather_what/value_12/","GET","200","","","","","example","",""
                # ==> "000000","0","x","/value_11/no_mather_what/value_22/","GET","200","","","","","example","",""
                # ==> "000000","0","x","/value_21/no_mather_what/value_12/","GET","200","","","","","example","",""
                # ==> "000000","0","x","/value_21/no_mather_what/value_22/","GET","200","","","","","example","",""
                
                entries = [line]
                extended_entries = []
    
                for variable in nikto_variables.keys():
                    for entry in entries:
                        if variable in entry:
                            begin, var, end = entry.partition(variable)
                            extended_entries.extend([begin + rpl + end for rpl in nikto_variables[variable]])
                        else:
                            extended_entries.append(entry)
                             
                    entries = extended_entries
                    extended_entries = []
                
                # once the line has been extended (if necessary) as multiple lines,
                # all these lines are parsed to extract the various fields.
    
                for entry in entries:
                    
                    entry = entry[1:-1]   # clean... remove 1st and last '"'
                    entry_fields = entry.split(u'","')
                    
                    if len(entry_fields) != 13:
                        
                        continue
                        
                    else:
                    
                        # ## NIKTO: db_tests ############################################################################################################################
                        #      0   ,     1    ,      2      ,  3  ,       4     ,  5    ,    6      ,    7     ,  8   ,     9   ,    10   ,    11     ,   12
                        # "Test-ID","OSVDB-ID","Tuning Type","URI","HTTP Method","Match","Match And","Match Or","Fail","Fail Or","Summary","HTTP Data","Headers"
                        #
                        # ## WEBSHAG test ###############################################################################################################################
                        #
                        # OSVDB | SERVER | METHOD | PATH | HEADER | DATA | MATCH_CODE | MATCH | MATCH_AND | MATCH_OR | FAIL_CODE | FAIL | FAIL_OR | DESCRIPTION | TRIGGER
                        
                        test = {}
                        test[u'OSVDB'] = entry_fields[1]
                        test[u'SERVER'] = u''
                        test[u'METHOD'] = entry_fields[4]
                        test[u'PATH'] = entry_fields[3]
                        test[u'HEADER'] = entry_fields[12]
                        test[u'DATA'] = entry_fields[11]
                        
                        # only one of the fields is allowed to have a code...
                        if HTTP_CODE_REGEXP.match(entry_fields[5]):
                            test[u'MATCH_CODE'] = entry_fields[5]
                            test[u'MATCH'] = u''
                            test[u'MATCH_AND'] = entry_fields[6]
                            test[u'MATCH_OR'] = entry_fields[7]
                            
                        elif HTTP_CODE_REGEXP.match(entry_fields[6]):
                            test[u'MATCH_CODE'] = entry_fields[6]
                            test[u'MATCH'] = entry_fields[5]
                            test[u'MATCH_AND'] = u''
                            test[u'MATCH_OR'] = entry_fields[7]
                        
                        elif HTTP_CODE_REGEXP.match(entry_fields[7]):
                            test[u'MATCH_CODE'] = entry_fields[7]
                            test[u'MATCH'] = entry_fields[5]
                            test[u'MATCH_AND'] = entry_fields[6]
                            test[u'MATCH_OR'] = u''
                            
                        else:
                            test[u'MATCH_CODE'] = u''
                            test[u'MATCH'] = entry_fields[5]
                            test[u'MATCH_AND'] = entry_fields[6]
                            test[u'MATCH_OR'] = entry_fields[7]
                        
                        if HTTP_CODE_REGEXP.match(entry_fields[8]):
                            test[u'FAIL_CODE'] = entry_fields[8]
                            test[u'FAIL'] = u''
                            test[u'FAIL_OR'] = entry_fields[9]
                        
                        elif HTTP_CODE_REGEXP.match(entry_fields[9]):
                            test[u'FAIL_CODE'] = entry_fields[9]
                            test[u'FAIL'] = entry_fields[8]
                            test[u'FAIL_OR'] = u''
                        else:
                            test[u'FAIL_CODE'] = u''
                            test[u'FAIL'] = entry_fields[8]
                            test[u'FAIL_OR'] = entry_fields[9]
                        
                        test[u'DESCRIPTION'] = entry_fields[10]
                        test[u'TRIGGER'] = u''
                        
                        nikto_tests.append(test)
    
    return nikto_tests

## ################################################################# ##

def db_load_known_banners():
    
    banners = {}
    field_separator = u'[::]'
    
    custom_db_dir = cfg_get_custom_db_dir(cfg_start_get())
    if not core_utilities.check_dir_path(custom_db_dir) or not os.path.exists(custom_db_dir + u'/' +  CUSTOM_DB_BANNERS):
        raise core_error.Config_Error(u'Invalid configuration value for \'custom_db_dir\' parameter')
    
    else:
        
        fileHandle = codecs.open(custom_db_dir + u'/' +  CUSTOM_DB_BANNERS, 'r', CUSTOM_DB_ENCODING)
        lines = fileHandle.readlines()
        fileHandle.close()
        
        for line in lines:
            line = line.strip()
            
            # skip comments or blank lines #
            if len(line) == 0 or line[0] == u'#':
                continue
            
            else:
                
                entry_fields = [e.strip() for e in line.split(field_separator)]
                
                if len(entry_fields) != 2:
                    continue
                
                else:
                    
                    try:
                        banners[re.compile(entry_fields[0], re.IGNORECASE)] = entry_fields[1]
                    except re.error:
                        print 'error'
                        continue
                    
    return banners


## ################################################################# ##

def db_load_custom_tests(triggers=[], host=None, load_generic=True):
    
    empty_field = u'__empty__'
    host_field = u'__host__'
    field_separator = u'[::]'
    custom_tests = []
    
    custom_db_dir = cfg_get_custom_db_dir(cfg_start_get())
    if not core_utilities.check_dir_path(custom_db_dir) or not os.path.exists(custom_db_dir + u'/' +  CUSTOM_DB_TESTS):
        raise core_error.Config_Error(u'Invalid configuration value for \'custom_db_dir\' parameter')
    
    else:
        # ## custom_test.db ####################################################################################################################################################
        #  0      1         2       3         4        5           6           7              8              9               10        11        12          13         14
        # id[::]server[::]method[::]path[::]header[::]data[::]match_code[::]indicator[::]indicator_and[::]indicator_or[::]fail_code[::]fail[::]fail_or[::]trigger[::]description
        #
        # ## WEBSHAG test ###############################################################################################################################
        #
        # OSVDB | SERVER | METHOD | PATH | HEADER | DATA | MATCH_CODE | MATCH | MATCH_AND | MATCH_OR | FAIL_CODE | FAIL | FAIL_OR | DESCRIPTION | TRIGGER
    
        fileHandle = codecs.open(custom_db_dir + u'/' +  CUSTOM_DB_TESTS, 'r', CUSTOM_DB_ENCODING)
        lines = fileHandle.readlines()
        fileHandle.close()
            
        for line in lines:
            line = line.strip()
            
            # skip comments or blank lines #
            if len(line) == 0 or line[0] == u'#':
                continue
            
            else:
                # maybe stripping is not a good idea...
                entry_fields = [e.strip() for e in line.split(field_separator)]
                
                if len(entry_fields) != 15:
                    continue
                    
                else:
                    
                    if (entry_fields[1] == empty_field and not load_generic):
                        continue
                    
                    if (entry_fields[1] != empty_field) and (entry_fields[1].lower() not in [t.lower() for t in triggers]):
                        continue
                        
                    else:
                        
                        for i in range(0, len(entry_fields)):
                            
                            if entry_fields[i] == empty_field:
                                entry_fields[i] = u''
                                
                            elif host_field in entry_fields[i]:
                                
                                if host != None:
                                    entry_fields[i] = entry_fields[i].replace(host_field, host)
                                else:
                                    entry_fields[i] = entry_fields[i].replace(host_field, u'')
                            else:
                                pass
                        
                        test = {}
                        test[u'OSVDB'] = u''
                        test[u'SERVER'] = entry_fields[1]
                        test[u'METHOD'] = entry_fields[2]
                        test[u'PATH'] = entry_fields[3]
                        test[u'HEADER'] = entry_fields[4]
                        test[u'DATA'] = entry_fields[5]
                        
                        test[u'MATCH_CODE'] = entry_fields[6]
                        test[u'MATCH'] = entry_fields[7]
                        test[u'MATCH_AND'] = entry_fields[8]
                        test[u'MATCH_OR'] = entry_fields[9]
                        
                        test[u'FAIL_CODE'] = entry_fields[10]
                        test[u'FAIL'] = entry_fields[11]
                        test[u'FAIL_OR'] = entry_fields[12]
                        
                        test[u'DESCRIPTION'] = entry_fields[14]
                        test[u'TRIGGER'] = entry_fields[13]
                        
                        custom_tests.append(test)
    
    return custom_tests

## ################################################################# ##

def db_nikto_update(db_tests, db_variables):
    
    # load config parameters #
    nikto_db_dir = cfg_get_nikto_db_dir(cfg_start_get())
    if not core_utilities.check_dir_path(nikto_db_dir):
        raise core_error.Config_Error(u'Invalid configuration value for \'nikto_db_dir\' parameter')
    
    else:
        
        fileHandle = codecs.open(nikto_db_dir + u'/' +  NIKTO_DB_VARIABLES, 'w', NIKTO_DB_ENCODING)
        fileHandle.write(db_variables)
        fileHandle.close()

        fileHandle = codecs.open(nikto_db_dir + u'/' +  NIKTO_DB_TESTS, 'w', NIKTO_DB_ENCODING)
        fileHandle.write(db_tests)
        fileHandle.close()

## ################################################################# ##

def db_custom_update(tests, banners):
    
    # load config parameters #
    custom_db_dir = cfg_get_custom_db_dir(cfg_start_get())
    if not core_utilities.check_dir_path(custom_db_dir):
        raise core_error.Config_Error(u'Invalid configuration value for \'custom_db_dir\' parameter')
    
    else:
        
        fileHandle = codecs.open(custom_db_dir + u'/' +  CUSTOM_DB_BANNERS, 'w', CUSTOM_DB_ENCODING)
        fileHandle.write(banners)
        fileHandle.close()

        fileHandle = codecs.open(custom_db_dir + u'/' +  CUSTOM_DB_TESTS, 'w', CUSTOM_DB_ENCODING)
        fileHandle.write(tests)
        fileHandle.close()


## ################################################################# ##
## FUZZER DATABASE FUNCTIONS
## ################################################################# ##
## These functions are relative to fuzzer databases.
## ################################################################# ##

def db_load_fuzzer_dirs():
    
    entries = []
    
    file = cfg_get_fuzzer_dir_list(cfg_start_get())
    if file != u'':
    
        if not core_utilities.check_file_path(file):
            raise core_error.Config_Error(u'Invalid configuration value for \'fuzzer_dir_list\' parameter')
        
        else:
        
            fileHandle = codecs.open(file, 'r', FILE_ENCODING)
            for line in fileHandle.readlines():
                
                if line[0] != FUZZ_DATABASE_COMMENT and len(line.split()) == 1:
                # Note: len(u'\r\n') = len(u'\n') = 0, thus empty lines are implicitely not considered.
                    entries.append(line.replace(u'\r', u'').replace(u'\n', u''))
                else:
                    continue
            fileHandle.close()
 
    return entries

## ##################################################################### ##

def db_load_fuzzer_files():
    
    entries = []
    
    file = cfg_get_fuzzer_file_list(cfg_start_get())
    if file != u'':
    
        if not core_utilities.check_file_path(file):
            raise core_error.Config_Error(u'Invalid configuration value for \'fuzzer_file_list\' parameter')
        
        else:
            
            fileHandle = codecs.open(file, 'r', FILE_ENCODING)
            for line in fileHandle.readlines():
                
                if line[0] != FUZZ_DATABASE_COMMENT and len(line.split()) == 1:
                # Note: len(u'\r\n') = len(u'\n') = 0, thus empty lines are implicitely not considered.
                    entries.append(line.replace(u'\r', u'').replace(u'\n', u''))
                else:
                    continue
            fileHandle.close()
            
    return entries

## ##################################################################### ##


def db_load_fuzzer_extensions():
    
    entries = []
    
    file = cfg_get_fuzzer_ext_list(cfg_start_get())
    if file != u'':
    
        if not core_utilities.check_file_path(file):
            raise core_error.Config_Error(u'Invalid configuration value for \'fuzzer_ext_list\' parameter')
        
        else:
            
            fileHandle = codecs.open(file, 'r', FILE_ENCODING)
            for line in fileHandle.readlines():
                
                if line[0] != FUZZ_DATABASE_COMMENT and len(line.split()) == 1:
                # Note: len(u'\r\n') = len(u'\n') = 0, thus empty lines are implicitely not considered.
                    entries.append(line.replace(u'\r', u'').replace(u'\n', u''))
                else:
                    continue
            fileHandle.close()
            
    return entries

## ################################################################# ##
## IDS EVASION FUNCTIONS
## ################################################################# ##
## These functions are relative to IDS evasion engine
## ################################################################# ##

def ids_load_proxy_list():
    
    field_separator = u'[::]'
    
    entries = []
    
    file = cfg_get_ids_rp_list(cfg_start_get())
    if not core_utilities.check_file_path(file):
        raise core_error.Config_Error(u'Invalid configuration value for \'ids_rp_list\' parameter')
    else:
        fileHandle = codecs.open(file, 'r', FILE_ENCODING)
        for line in fileHandle.readlines():
            
            if line.strip()[0] == u'#':
                continue
            else:
                params = [p.strip() for p in line.split(field_separator)]
                if len(params) == 4:
                    if core_utilities.check_host(params[0]) and core_utilities.check_port_string(params[1]) and core_utilities.check_generic_string(params[2]) and core_utilities.check_generic_string(params[3]):
                        entries.append(params)
                    else:
                        continue
                else:
                    continue
            
        fileHandle.close()
        
    return entries


## ################################################################# ##
## EXPORT RELATED FUNCTIONS
## ################################################################# ##
## These functions are relative to reporting
## ################################################################# ##

def exp_write_report(document, filename):
    
    file = codecs.open(filename, "w", FILE_ENCODING)
    file.write(document)
    file.close()

    
