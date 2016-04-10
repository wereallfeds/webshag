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

from __future__ import with_statement
from socket import gethostbyname
from urlparse import urlparse
from xml.dom.minidom import parseString
from webshag.core import core_file, core_http, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

WS_ENDPOINT = u'http://soap.search.msn.com:80/webservices.asmx'
WS_ENCODING = u'utf-8'

## ################################################################# ##
## CLI OUTPUT FUNCTIONS
## ################################################################# ##
## The possible result configurations issued by this module are:
## Generic error:           {ERROR}
## Target specification:    {IPADDRESS, TARGET}
## Vhost on target:         {IPADDRESS, VHOST}
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
        print '% DOM %\t' + result[u'VHOST']

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##
## The functions below are used to INTERFACE this module with upper
## layers. As long as these functions exist (and have the same input
## and output parameters) all the rest of the module can be modified
## without interfering with upper levels using it.
## ################################################################# ##

def perform(target, cli, results, results_lock, switch, switch_lock):

# Input:  target - unicode - target machine (IPv4 or hostname)
#         cli - boolean - set verbosity on STDOUT to ON/OFF
#         results - [dict] - (shared) output results list
#         results_lock - threading.Lock - (shared) lock on the output list
#         switch - [boolean] - (shared) switch controlling scan life-cycle (ON/OFF)
#         switch_lock - threading.Lock - (shared) lock on switch
#
# Return: (void)
#
# This function is in charge of retrieving all the referenced domains
# that are hosted at given IP address (or at the IP address corresponding
# to the given hostname). For this, the LIVE search webservice is used,
# a valid Live AppID is needed (stored in the configuration file).
    
    try:
        # load the Live ID from the configuration file 
        live_id = core_file.cfg_get_live_id(core_file.cfg_start_get())
        if not core_utilities.check_live_id(live_id):
            
            __issue_result(results, results_lock, cli, {u'ERROR': u'Invalid LIVE ID. Please verify configuration file.'})
            
        else:
            
            domains = []
            limit_iteration = 10
            offset = 0
            count = 50
            iteration = 1
            found = 0
            
            path = urlparse(WS_ENDPOINT).path
            port = urlparse(WS_ENDPOINT).port
            host = urlparse(WS_ENDPOINT).netloc.replace(u':' + unicode(port), u'')
            
            ip_address = gethostbyname(target)
            httpClient = core_http.HTTPClient(host, port, True)
            
            # test if web service is up and valid...
            http_test = core_http.test_http(host, port, override_disable_ssl = True)
            if not http_test[0]:
                error_message = http_test[1]
                
                __issue_result(results, results_lock, cli, {u'ERROR': u'Web service end-point: ' + error_message})
                
            else:
                
                __issue_result(results, results_lock, cli, {u'IPADDRESS': ip_address, u'TARGET': ip_address})
                
                while iteration < limit_iteration:
                    
                    
                    # crafting the HTTP request #
                    httpRequest = core_http.HTTPRequest()
                    httpRequest.set_method(u'POST')
                    httpRequest.set_path(path)
                    httpRequest.set_data(__soap_live_request(live_id, ip_address, offset, count))
                    
                    # sending the HTTP request #
                    httpResponse = httpClient.perform_request(httpRequest)
                
                    if httpResponse != None:
                        
                        if httpResponse.get_code() == u'200':
                            
                            parsedData = parseString(httpResponse.get_data().encode(WS_ENCODING))
                            
                            # checking if the request produced a SOAP error #
                            faults = parsedData.getElementsByTagName(u'soapenv:Fault')
                            if len(faults) > 0:
                                
                                errorMessage = faults[0].getElementsByTagName(u'detail')[0].firstChild.data.strip()
                                
                                __issue_result(results, results_lock, cli, {u'ERROR': u'SOAP error: ' + errorMessage})
                                
                                break
                            
                            # processing the results #
                            res = parsedData.getElementsByTagName(u'Result')
                            if len(res) > 0:
                                for item in res:
                                    for url_item in item.getElementsByTagName(u'Url'):
                                        url = url_item.firstChild.data.strip()
                                        domain = urlparse(url).netloc
                                        if domain not in domains:
                                            domains.append(domain)
                                            
                                            __issue_result(results, results_lock, cli, {u'IPADDRESS': ip_address, u'VHOST': domain})
                                            
                                            found += 1
                                    offset += 1
                                iteration += 1
                                parsedData.unlink()
                            else:
                                # If there are no more results left, exit the loop,
                                # even if limit_iteration is not reached.
                                break
                        else:
                            break
                    else:
                        break
                    
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

def __soap_live_request(id, ip, offset, count):

    live_request = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body>\
    <Search xmlns="http://schemas.microsoft.com/MSNSearch/2005/09/fex"><Request><AppID>' + id + '</AppID><Query>ip:' + ip + '</Query>\
    <CultureInfo>en-US</CultureInfo><SafeSearch>Off</SafeSearch><Flags>None</Flags><Requests><SourceRequest><Source>Web</Source>\
    <Offset>' + unicode(offset) + '</Offset><Count>' + unicode(count) + '</Count><ResultFields>All</ResultFields></SourceRequest>\
    </Requests></Request></Search></soapenv:Body></soapenv:Envelope>'
    
    return live_request
