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

from __future__ import with_statement
import subprocess
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError
from webshag.core import core_file, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

NMAP_OPT = ['-A',  '-P0', '--open', '--no-stylesheet', '-oX', '-']

## ################################################################# ##
## CLI OUTPUT FUNCTIONS
## ################################################################# ##
## The possible result configurations issued by this module are:
## Generic error:           {ERROR}
## Target specification:    {HOST, IPADDRESS, TARGET}
## Open port:               {HOST, IPADDRESS, SCANNER,
##                           PORTID*, PROTOCOL*, SRV_NAME*,
##                           SRV_PRODUCT*, SRV_OS* }
## Note: starred (*) keys may be missing
## ################################################################# ##

def cli_output_result(result):
    
    if result.has_key(u'ERROR'):
        print '% ERROR %\t' + result[u'ERROR']
        
    elif result.has_key(u'TARGET'):
        print ''
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        print result[u'TARGET']
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
    
    else:
        print '% PORT %\t' + result[u'PORTID'] + u' (' + result[u'PROTOCOL'] + u')'
        
        if result.has_key(u'SRV_NAME'):
            print '% SRVC %\t' + result['SRV_NAME']
            
            if result.has_key(u'SRV_PRODUCT'):
                print '% PROD %\t' + result['SRV_PRODUCT']
                
                if result.has_key(u'SRV_OS'):
                    print '% SYST %\t' + result['SRV_OS']
                    
        print u''

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##
## The functions below are used to INTERFACE this module with upper
## layers. As long as these functions exist (and have the same input
## and output parameters) all the rest of the module can be modified
## without interfering with upper levels using it.
## ################################################################# ##

def perform(host, cli, results, results_lock, switch, switch_lock):

# Input:  host - unicode - target host
#         cli - boolean - set verbosity on STDOUT to ON/OFF
#         results - [dict] - (shared) output results list
#         results_lock - threading.Lock - (shared) lock on the output list
#         switch - [boolean] - (shared) switch controlling scan life-cycle (ON/OFF)
#         switch_lock - threading.Lock - (shared) lock on switch
#        
# Return: (void)
#
# This function relies on Nmap to scan TCP ports of target host.
 
    try:
        # loading parameters from config file
        cfp = core_file.cfg_start_get()
        nmap = core_file.cfg_get_nmap(cfp)
        nmap_location = core_file.cfg_get_nmap_location(cfp)
        if core_utilities.check_file_path(nmap_location):
            
            if nmap:
                __nmap_scan(host, cli, results, results_lock)
            else:
                __issue_result(results, results_lock, cli, {u'ERROR': u'Nmap missing. Please install Nmap or/and verify configuration.'})
                
        else:
            __issue_result(results, results_lock, cli, {u'ERROR': u'Invalid configuration parameters. Please verify configuration file.'})
            
    except core_error.Config_Error, e:
        __issue_result(results, results_lock, cli, {u'ERROR': e.error_message})


## ################################################################# ##
## PRIVATE FUNCTIONS
## ################################################################# ##
## These are internal functions. The are only called from inside
## this module and cannot be accessed from outside.
## ################################################################# ##

def __issue_result(results, results_lock, cli, result):
    with results_lock:
        results.append(result)
        if cli:
            cli_output_result(result)

## ################################################################# ##

def __nmap_scan(host, cli, results, results_lock):
    
    nmap_location = core_file.cfg_get_nmap_location(core_file.cfg_start_get())
    ipaddress = core_utilities.get_ip_address(host)
    
    __issue_result(results, results_lock, cli, {u'HOST': host, u'IPADDRESS': ipaddress, u'TARGET': host})
    
    # building the nmap command
    command = [nmap_location]
    command.extend(NMAP_OPT)
    command.append(host)
    
    try:
        # running nmap as a subprocess
        (stdout, stderr) = subprocess.Popen(command, stdout=subprocess.PIPE, shell=False).communicate()
        results_xml = parseString(stdout)       
        
        # parsing the XML output of Nmap
        for port_element in results_xml.getElementsByTagName(u'port'):
            
            result = {}
            result[u'HOST'] = host
            result[u'IPADDRESS'] = ipaddress
            result[u'SCANNER'] = u'nmap'
            
            if port_element.attributes.has_key(u'protocol'):
                result[u'PROTOCOL'] = port_element.attributes[u'protocol'].value
            if port_element.attributes.has_key(u'portid'):
                result[u'PORTID'] = port_element.attributes[u'portid'].value
                
            for service_element in port_element.getElementsByTagName(u'service'):
                if service_element.attributes.has_key(u'name'):
                    result[u'SRV_NAME'] = service_element.attributes[u'name'].value
                if service_element.attributes.has_key(u'product'):
                    result[u'SRV_PRODUCT'] = service_element.attributes[u'product'].value
                if service_element.attributes.has_key(u'ostype'):
                    result[u'SRV_OS'] = service_element.attributes[u'ostype'].value
            
            __issue_result(results, results_lock, cli, result)
        
    # this is used when Ctrl-C is sent in CLI mode to avoid,
    # an error of XML parser when Nmap is killed...
    except ExpatError:
        pass