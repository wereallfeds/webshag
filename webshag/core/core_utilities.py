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
## last mod: 2008-04-18

import re
import socket
import string
import os.path
from string import letters
from random import choice

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

IPV4_REGEXP = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
# http://www.regular-expressions.info/examples.html

## ################################################################# ##
## MISC FUNCTIONS
## ################################################################# ##

def get_ip_address(host):
    return socket.gethostbyname(host)

def random_string(size):
    return u''.join([choice(letters) for i in range(size)])

## ################################################################# ##
## INPUT VALIDATION FUNCTIONS
## ################################################################# ##
## These functions are used to validate user input coming from input
## parameters (GUI/CLI) and from configuration file.
## ################################################################# ##

def check_http_codes(http_codes):
    
    codes = [c.strip() for c in http_codes.split(u',')]
    for code in codes:
        if code.isdigit():
            if int(code) > 100 and int(code) < 600:
                continue
            else:
                return False
        else:
            return False
    return True

## ################################################################# ##

def check_threads(threads):
    
    if type(threads) == type(1) and threads > 0 and threads < 50:
        return True
    else:
        return False

## ################################################################# ##

def check_host(host):
    
    valid = True
    
    if isinstance(host, basestring) and len(host) > 0:
        if not IPV4_REGEXP.match(host):
            try:
                socket.gethostbyname(host.encode(u'ascii', u'strict'))
            except UnicodeEncodeError:
                valid = False
            except socket.error:
                valid = False
        else:
            pass
    else:
        valid = False
    
    return valid

## ################################################################# ##

def check_host_list(hosts):
    host_list = [h.strip() for h in hosts.split(u',')]
    
    for host in host_list:
        if not check_host(host):
            return False
    
    return True

## ################################################################# ##

def check_port_list(ports):
    port_list = [p.strip() for p in ports.split(u',')]
    
    for port in port_list:
        if not check_port_string(port):
            return False
    
    return True


## ################################################################# ##

def check_port_string(port):
    
    valid = True
    
    try:
        valid = check_port_int(int(port))
    
    except ValueError:
        valid = False
    
    return valid

## ################################################################# ##
    
def check_port_int(port):
    
    valid = True
    
    if type(port) != type(1):
        valid = False
    else:                       
        if port < 1 or port > 65535:
            valid = False
    
    return valid

## ################################################################# ##

def check_root(root):
    
    if len(root) > 0 and root[0] == u'/' and root[-1] == u'/':
        valid = True
    else:
        valid = False
    
    return valid

## ################################################################# ##

def check_root_list(root_list):
    
    roots = [r.strip() for r in root_list.split(u',')]
    
    for root in roots:
        if not check_root(root):
            return False
    
    return True

## ################################################################# ##

def check_spider_root(root):
    
    if len(root) > 0 and root[0] == u'/':
        valid = True
    else:
        valid = False
    
    return valid
    
## ################################################################# ##

def check_extension(extension):
    
    valid = True
    
    if len(extension) > 0 and extension[0] != u'.':
        valid = False
    if len(extension) > 0 and len(extension) < 2:
        valid = False
    if u' ' in extension:
        valid = False
    
    return valid

## ################################################################# ##

def check_boolean(boolean):
    return type(boolean) == type(True)

## ################################################################# ##

def check_file_path(path):
    
    if len(path) > 0 and os.path.isfile(path):
        return True
    else:
        return False

## ################################################################# ##

def check_save_file_path(file):
    if check_dir_path(os.path.dirname(file)) and check_simple_filename(os.path.basename(file)):
        return True
    else:
        return False

## ################################################################# ##

def check_dir_path(path):
    
    if len(path) > 0 and os.path.isdir(path):
        return True
    else:
        return False

## ################################################################# ##

def check_timeout(timeout):
    
    if type(timeout) == type(1) and timeout >= 0:
        return True
    else:
        return False
    
## ################################################################# ##

def check_ascii_string(text):
    try:
        text.decode('ascii', 'strict')
        return True
    except UnicodeDecodeError:
        return False
## ################################################################# ##

def check_simple_filename(file):
    if not isinstance(file, basestring):
        return False
    
    for letter in file:
        if not letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789._-':
            return False
    
    return True

## ################################################################# ##

def check_http_method(method, basic=True):
    methods = [u'OPTIONS', 'HEAD', u'GET', u'POST', u'PUT', u'DELETE', u'TRACE', u'CONNECT']
    methods_basic = ['HEAD', u'GET', u'POST']
    
    if basic and method in methods_basic:
        return True
    elif not basic and method in methods:
        return True
    else:
        return False
    
## ################################################################# ##

def check_generic_string(text):
    if isinstance(text, basestring):
        return True
    else:
        return False

## ################################################################# ##
    
def check_live_id(id):
    valid = True
    for c in id:
        if c not in string.hexdigits:
            valid = False
    return valid

## ################################################################# ##
    
def check_fuzz_config(cfg):
    if cfg == u'00' or cfg == u'01' or cfg == u'10' or cfg == u'11':
        return True
    else:
        return false
