#!/usr/bin/python
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

## ################################################################# ##
##                                INIT                               ##
## ################################################################# ##

path_prefix = os.path.abspath(os.path.curdir) + '/'

## ################################################################# ##
##                            CONSTANTS                              ##
## ################################################################# ##

NMAP = u'/usr/bin/nmap'
CORE_FILE = u'webshag/core/core_file.py'
CFG_FILE = u'config/webshag.conf'
FUZZ_DIRS = path_prefix + u'/database/fuzzer/directory-list-2.3-small.txt'
FUZZ_FILES = path_prefix + u'/database/fuzzer/directory-list-1.0.txt'
FUZZ_EXT = path_prefix + u'/database/fuzzer/extensions.txt'
CUSTOM_DB = path_prefix + u'/database/custom'
NIKTO_DB = path_prefix + u'/database/nikto'
IDS_PROXIES = path_prefix + u'/database/proxies/proxies.txt'

CORE_CFG_RE = re.compile(ur'CFG_FILE\s=\s(?P<path>.*)')

## ################################################################# ##
##                         NMAP PORT SCANNER                         ##
## ################################################################# ##

print u'[*] Looking for Nmap on your system...\t',

if os.path.exists(NMAP):
    nmap = u'True'
    nmap_location = NMAP
    print u'Found!'

else:
    print u'Not Found!'
    user_nmap = raw_input(u'[#] Please specify Nmap (nmap.exe) location (blank to skip): ')
    if user_nmap != '':
        if os.path.isfile(user_nmap):
            nmap = 'True'
            nmap_location = user_nmap
        else:
            nmap = u'False'
            nmap_location = ''
            print u'[!] Nmap has not been found. Port scan module will not be functional.'
    else:
        nmap = u'False'
        nmap_location = ''
        print u'[!] Nmap has not been found. Port scan module will not be functional.'

## ################################################################# ##
##                         LIVE SEARCH APPID                         ##
## ################################################################# ##

user_live = raw_input(u'[#] Enter your Live Search AppID (blank to skip): ')
if user_live != '':
    live_id = user_live
    print u'[*] Live Search AppID: ' + user_live + u'\t Done!'
else:
    live_id = ''
    print u'[!] AppID missing. Domain information module will not be functional.'

## ################################################################# ##
##                          ALTERING FILES                           ##
## ################################################################# ##

core_file = path_prefix + CORE_FILE
cfg_file = path_prefix + CFG_FILE


# core_file.py
print u'[*] Patching source code (configuration file location)...\t',
# reading file
core_file_handler = codecs.open(core_file, u'r', u'utf-8')
core_file_contents = core_file_handler.read()
core_file_handler.close()
# replacing path value
old_path = CORE_CFG_RE.findall(core_file_contents)[-1]
core_file_contents = core_file_contents.replace(old_path, '\'' + cfg_file + '\'')
# writing file back
core_file_handler = codecs.open(core_file, u'w', u'utf-8')
core_file_handler.write(core_file_contents)
core_file_handler.close()
print u'Done!'

# webshag.conf
print u'[*] Fixing configuration file settings...\t',
configParser = SafeConfigParser()
configParser.readfp(codecs.open(cfg_file, u'r', u'utf-8')) 
configParser.set(u'core_file', u'fuzzer_file_list', FUZZ_FILES)
configParser.set(u'core_file', u'fuzzer_dir_list', FUZZ_DIRS)
configParser.set(u'core_file', u'fuzzer_ext_list', FUZZ_EXT)
configParser.set(u'core_file', u'custom_db_dir', CUSTOM_DB)
configParser.set(u'core_file', u'nikto_db_dir', NIKTO_DB)
configParser.set('core_http', 'ids_rp_list', IDS_PROXIES)
configParser.set(u'module_info', u'live_id', live_id)
configParser.set(u'module_portscan', u'nmap', nmap)
configParser.set(u'module_portscan', u'nmap_location', nmap_location)
cfg_file_handler = codecs.open(cfg_file, u'w', u'utf-8')
configParser.write(cfg_file_handler)
cfg_file_handler.close()
print u'Done!'

## ################################################################# ##
##                                 END                               ##
## ################################################################# ##

print ''
print 'Thanks for your interest in webshag! It is now ready to be used!'
print 'Enjoy! For more information please visit www.scrt.ch'
print ''
raw_input('Press any key to exit.\n')
