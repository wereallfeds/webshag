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
## last mod: 2008-02-18

import os.path
from webshag.core import core_file, core_http

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

HOST_CIRT = u'www.cirt.net'
PATH_NIKTO_TESTS = u'/nikto/UPDATES/2.02/db_tests'
PATH_NIKTO_VARIABLES = u'/nikto/UPDATES/2.02/db_variables'

HOST_CUSTOM = u'www.scrt.ch'
PATH_CUSTOM_TESTS = u'/outils/webshag/custom_tests.db'
PATH_CUSTOM_BANNERS = u'/outils/webshag/banners.db'

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##

def update_nikto_database():
    
    test = core_http.test_http(HOST_CIRT, 80)
    
    if test[0]:    
    
        httpClient = core_http.HTTPClient(HOST_CIRT, 80)
        
        request_tests = core_http.HTTPRequest()
        request_tests.set_method('GET')
        request_tests.set_path(PATH_NIKTO_TESTS)
        response_tests = httpClient.perform_request(request_tests)
        
        request_vars = core_http.HTTPRequest()
        request_vars.set_method('GET')
        request_vars.set_path(PATH_NIKTO_VARIABLES)
        response_vars = httpClient.perform_request(request_vars)
        
        if response_tests != None and response_vars != None:
            
            if response_tests.get_code() == u'200' and response_vars.get_code() == u'200':
                
                db_vars = response_vars.get_data()
                db_tests = response_tests.get_data()
                
                try:
                    core_file.db_nikto_update(db_tests, db_vars)
                    return True
                
                except IOError: # typically: permission denied....
                    return False
            else:
                return False
        else:
            return False
    else:
        return False
    
## ################################################################# ##
    
def update_custom_database():
    
    test = core_http.test_http(HOST_CUSTOM, 80)
    
    if test[0]:
        
        httpClient = core_http.HTTPClient(HOST_CUSTOM, 80)
        
        request_tests = core_http.HTTPRequest()
        request_tests.set_method('GET')
        request_tests.set_path(PATH_CUSTOM_TESTS)
        response_tests = httpClient.perform_request(request_tests)
        
        request_banners = core_http.HTTPRequest()
        request_banners.set_method('GET')
        request_banners.set_path(PATH_CUSTOM_BANNERS)
        response_banners = httpClient.perform_request(request_banners)
        
        if response_tests != None and response_banners != None:
            
            if response_tests.get_code() == u'200' and response_banners.get_code() == u'200':
                
                db_banners = response_banners.get_data()
                db_tests = response_tests.get_data()
                
                try:
                    core_file.db_custom_update(db_tests, db_banners)
                    return True
                
                except IOError: # typically: permission denied....
                    return False
            else:
                return False
        else:
            return False
    else:
        return False