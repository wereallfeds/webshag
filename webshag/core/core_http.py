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
## last mod: 2008-09-09

import re
import httplib
import socket
import hashlib
import urlparse
from hashlib import md5
from base64 import b64encode
from urllib import quote, unquote
from string import upper, lower
from random import choice
from time import sleep

import core_file, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

BASE_ENCODING = u'ascii'
# Used to encode/decode generic cases from/to UNICODE

NETWORK_ENCODING = u'ascii'
# Encoding used before sending the request to ** httplib ** methods

DEFAULT_DECODING = u'iso-8859-1'
# Default encoding used to decode web pages (as specified in RFC 2616)

QUOTE_ENCODING = u'utf-8' 
# Used as a transition encoding when 'quoting' URLs
# (ref: http://www.w3.org/International/O-URL-code.html)

PASSWORD_ENCODING = u'utf-8'

URL_SAFE_CHARS = "$-_.+!*'(),;/?:@=&"
# Characters that should not be replaced by %XX in URLs

REDIRECTION = [u'301', u'302', u'303', u'307']

HTML_TAG_REGEXP = re.compile(r'</?(?P<tag>[\w]+)[\s|>]', re.IGNORECASE)


## ################################################################# ##
## FUNCTIONS
## ################################################################# ##

def test_http(host, port, method = u'GET', override_disable_ssl = False):
    
    try:
        httpClient = HTTPClient(host, port, override_disable_ssl)
        request = HTTPRequest()
        request.set_method(method)
        request.set_path(u'/')
        response = httpClient.perform_request(request)
        
        if response != None:
            if response.get_code() == u'501':
                return (False, u'HTTP method not supported: ' + method)
            
            elif response.get_code() == u'407':
                return (False, u'Proxy authentication failed.')
            
            else:
                return (True, u'')
            
        else:
            return (False, u'HTTP Request failed. Target may not be an HTTP server or timeout may be too short.')
        
    except socket.error:
        return (False, 'Connection Failed. Host/port may be invalid or settings (SSL, proxy,...) may be wrong.')


## ################################################################# ##

def fingerprint_response(httpRequest, httpResponse):
    
    if httpResponse != None:
    
        code = httpResponse.get_code()
        rawtype = httpResponse.get_header('content-type')
        if rawtype != None:
            type = rawtype.split(u';')[0]
        else:
            type = None
        body = httpResponse.get_data()
        
        if code in REDIRECTION:
            
            location_1 = httpResponse.get_header(u'location')
            location_2 = urlparse.urlparse(location_1).path
            #location2 = location1.replace(httpRequest.get_path(True), u'')
            #location2 = location1.replace(httpRequest.get_path(False), u'')
            
            
            if location_1 != None and location_2 != None:
                
                hash_1 = unicode(md5(location_1).hexdigest())
                hash_2 = unicode(md5(location_2).hexdigest())
                
            else:
                # If the response is a redirection but has no 'location' header (this should
                # never happen, it's just in case of...) 
                hash_1 = None
                hash_2 = None
                
            return (code, type, hash_1, hash_2)
            
        else:
            # The fingerprint of an HTTP response is the MD5 sum of the
            # body and the MD5 sum of the HTML tags.
            
            body = body.replace(httpRequest.get_path(True), u'')
            body = body.replace(httpRequest.get_path(False), u'')
            
            hash_1 = md5(body.encode('ascii', u'ignore')).hexdigest()
            
            if type != None and 'html' in type:
                tags = u''.join(HTML_TAG_REGEXP.findall(body))
                hash_2 = md5(tags.encode('ascii', u'ignore')).hexdigest()
            else:
                hash_2 = None
            
            return (code, type, hash_1, hash_2)
        
    else:
        return None

## ################################################################# ##

def test_response_fingerprint(fingerprint, reference, risk=True):
    
    if fingerprint != None and reference != None:

        if fingerprint[0] == reference[0]: # codes match
            
            # types are not None => consider them
            if fingerprint[1] != None and reference[1] != None:
                
                if fingerprint[1] == reference[1]: # types match
                    
                    # if MD5 hash matches
                    if fingerprint[2] != None and reference[2] != None and fingerprint[2] == reference[2]:
                        return True
                    
                    # if MD5 hash of HTML tags matches
                    elif risk and fingerprint[3] != None and reference[3] != None and fingerprint[3] == reference[3]:
                        return True
                    
                    else: # no hash matches
                        return False
                    
                else: # types do not match
                    return False
                
            # types are None => ignore them
            elif fingerprint[1] == None and reference[1] == None:
                
                # if MD5 hash matches
                if fingerprint[2] != None and reference[2] != None and fingerprint[2] == reference[2]:
                    return True
                # if MD5 hash of HTML tags matches
                elif risk and fingerprint[3] != None and reference[3] != None and fingerprint[3] == reference[3]:
                    return True
                else: # no hash matches
                    return False
                
            else: # types do not match
                return False
            
        else: # codes don't match
            return False
        
    else: # fingerprinting failed
        return False


## ################################################################# ##
## PUBLIC CLASS: HTTPClient
## ################################################################# ##
## This class implements a simple HTTP client used by modules to
## send HTTP requests. The main goal of implementing a custom HTTP
## client (based directly on httplib instead of higher level
## libraries like urllib2) is to have full access to all the needed
## parameters and to make it lower level (control on redirections...)
## ################################################################# ##

class HTTPClient(object):

    def __init__(self, host, port, override_disable_ssl = False):
        
        self.__host = host
        self.__port = port
        
        # Loading and checking the configuration settings
        
        configParser = core_file.cfg_start_get()
        
        self.__user_agent = core_file.cfg_get_user_agent(configParser)
        if not core_utilities.check_ascii_string(self.__user_agent):
            raise core_error.Config_Error(u'Invalid configuration value for \'user_agent\' parameter')
        
        self.__socket_timeout = core_file.cfg_get_socket_timeout(configParser)
        
        self.__ssl = core_file.cfg_get_ssl(configParser)
        
        self.__ids = core_file.cfg_get_ids(configParser)
        
        self.__ids_rp = core_file.cfg_get_ids_rp(configParser)
        if self.__ids and not core_utilities.check_boolean(self.__ids_rp):
            raise core_error.Config_Error(u'Invalid configuration value for \'ids_rp\' parameter')
        
        self.__ids_rp_list = core_file.cfg_get_ids_rp_list(configParser)
        if self.__ids and self.__ids_rp and not core_utilities.check_file_path(self.__ids_rp_list):
            raise core_error.Config_Error(u'Invalid configuration value for \'ids_rp_list\' parameter')
        
        self.__ids_pause = core_file.cfg_get_ids_pause(configParser)
        
        self.__ids_pause_time = core_file.cfg_get_ids_pause_time(configParser)
        
        self.__proxy = core_file.cfg_get_proxy(configParser)

        self.__proxy_host = core_file.cfg_get_proxy_host(configParser)
        if self.__proxy and not core_utilities.check_host(self.__proxy_host):
            raise core_error.Config_Error(u'Invalid configuration value for \'proxy_host\' parameter')
        
        self.__proxy_port = core_file.cfg_get_proxy_port(configParser)
        
        self.__proxy_auth = core_file.cfg_get_proxy_auth(configParser)
        if self.__proxy and not core_utilities.check_boolean(self.__proxy_auth):
            raise core_error.Config_Error(u'Invalid configuration value for \'proxy_auth\' parameter')
        
        self.__proxy_username = core_file.cfg_get_proxy_username(configParser)
        if self.__proxy and self.__proxy_auth and not core_utilities.check_generic_string(self.__proxy_username):
            raise core_error.Config_Error(u'Invalid configuration value for \'proxy_username\' parameter')
        
        self.__proxy_password = core_file.cfg_get_proxy_password(configParser)
        if self.__proxy and self.__proxy_auth and not core_utilities.check_generic_string(self.__proxy_password):
            raise core_error.Config_Error(u'Invalid configuration value for \'proxy_password\' parameter')
        
        self.__auth = core_file.cfg_get_auth(configParser)
        
        self.__auth_username = core_file.cfg_get_auth_username(configParser)
        if self.__auth and not core_utilities.check_generic_string(self.__auth_username):
            raise core_error.Config_Error(u'Invalid configuration value for \'auth_username\' parameter')
            
        self.__auth_password = core_file.cfg_get_auth_password(configParser)
        if self.__auth and not core_utilities.check_generic_string(self.__auth_password):
            raise core_error.Config_Error(u'Invalid configuration value for \'auth_password\' parameter')
        
        self.__default_header = core_file.cfg_get_default_header(configParser)
        if len(self.__default_header) != 0 and not core_utilities.check_generic_string(self.__default_header):
            raise core_error.Config_Error(u'Invalid configuration value for \'default_header\' parameter')
        
        self.__default_header_value = core_file.cfg_get_default_header_value(configParser).strip()
        if not core_utilities.check_generic_string(self.__default_header_value):
            raise core_error.Config_Error(u'Invalid configuration value for \'default_header_value\' parameter')
        
        core_file.cfg_end_get(configParser)
        
        if self.__ssl and self.__ids and self.__ids_rp:
            raise core_error.Config_Error(u'Incompatible configuration settings: \'ssl\' and \'ids_rp\'.')
        
        if self.__proxy and self.__ids and self.__ids_rp:
            raise core_error.Config_Error(u'Incompatible configuration settings: \'proxy\' and \'ids_rp\'.')

        if self.__ids and self.__ids_rp:
            self.__ids_proxies = core_file.ids_load_proxy_list()
            
            if len(self.__ids_proxies) == 0:
                raise core_error.Config_Error(u'Proxy list is empty!')
        
        if self.__proxy: # proxy
            
            if self.__ssl and not override_disable_ssl:
                raise core_error.Config_Error(u'No support for HTTPS proxy.')
                # TODO: implement...
                
            else:
                self.__url_prefix = u'http://' + self.__host + u':' + unicode(self.__port)
            
            # proxy BASIC authentication #
            if self.__proxy_auth:
                self.__proxy_credentials = self.__basic_authentication(self.__proxy_username, self.__proxy_password)
            
            # connection to proxy
            self.__connection = httplib.HTTPConnection(self.__proxy_host, self.__proxy_port)
        
        else: # no proxy
            
            if self.__ids and self.__ids_rp:
                self.__connection = None
                
            else:
                if self.__ssl and not override_disable_ssl: # HTTPS connection
                    self.__connection = httplib.HTTPSConnection(self.__host, self.__port)
                else: # HTTP connection
                    self.__connection = httplib.HTTPConnection(self.__host, self.__port)
                    
                self.__url_prefix = u''

        socket.setdefaulttimeout(self.__socket_timeout)
    
    ## ################################################################# ##
    
    def perform_request(self, httpRequest):
        
        failsafe = False
        failcount = 0
        
        while not failsafe and failcount < 2:
            failsafe = True
            
            try:
                
                # addind the user-agent header
                httpRequest.set_header(u'user-agent', self.__user_agent)
                
                # adding the proxy authentication if necessary
                if self.__proxy and self.__proxy_auth:
                    httpRequest.set_header(u'proxy-authorization', u'Basic ' + self.__proxy_credentials)
                
                # calling the IDS evasion engine #
                if self.__ids:
                    httpRequest = self.__ids_evasion(httpRequest)
                    
                # adding default header
                if len(self.__default_header) != 0:
                    httpRequest.set_header(self.__default_header, self.__default_header_value)
                    
                # REMOVE BEFORE FLIGHT *************
                self.__connection.set_debuglevel(0)
                # **********************************
                
                # managing authentication
                if self.__auth:
                    # if auth is enabled, include by default basic headers and send a test request
                    httpRequest.set_header(u'authorization', u'Basic ' + self.__basic_authentication(self.__auth_username, self.__auth_password))
                    tmpHttpRsp = self.__sendRequest(httpRequest)
                    
                    # if 401 received
                    if tmpHttpRsp != None and tmpHttpRsp.get_code() == u'401':
                        
                        authHeader = tmpHttpRsp.get_header(u'www-authenticate')
                        type, space, details = [s.strip() for s in authHeader.partition(u' ')]
                        
                        # if type of authentication required is digest => retry in digest mode
                        if lower(type) == u'digest':
                            
                            credentials = self.__digest_authentication(authHeader, httpRequest.get_method(), httpRequest.get_path(False), self.__auth_username, self.__auth_password)
                            httpRequest.set_header(u'authorization', u'Digest ' + credentials)
                        
                        # if the type required is not digest => credentials are wrong, return as is
                        else:
                            return tmpHttpRsp
                        
                    elif tmpHttpRsp != None:
                        return tmpHttpRsp
                    
                    else:
                        return None
                
                # sending the request
                httpResponse = self.__sendRequest(httpRequest)
                
                return httpResponse
            
            except socket.timeout:
                failsafe = False
                failcount += 1
                continue
            
            except socket.error:
                self.__connection.close()
                self.__connection.connect()
                failsafe = False
                failcount += 1
                continue
        
            except httplib.HTTPException:
                self.__connection.close()
                self.__connection.connect()
                failsafe = False
                failcount += 1
                continue
        
        # if failed 2 times...
        return None
        
    ## ################################################################# ##
    
    def __ids_evasion(self, httpRequest):
        
        if self.__ids_rp:
            
            # random proxy #
            proxy = choice(self.__ids_proxies)
            self.__connection = httplib.HTTPConnection(proxy[0], int(proxy[1]))
            
            if self.__ssl:
                self.__url_prefix = u'https://' + self.__host + u':' + unicode(self.__port)
            else:
                self.__url_prefix = u'http://' + self.__host + u':' + unicode(self.__port)
                
            proxy_credentials = self.__basic_authentication(proxy[2], proxy[3])
            httpRequest.set_header(u'proxy-authorization', u'Basic ' + proxy_credentials)
        
        if self.__ids_pause:
            ptime = choice(range(0, self.__ids_pause_time + 1))
            sleep(ptime)
            
        return httpRequest
    
    ## ################################################################# ##
    
    
    # ###################################################### #
    # BASIC AUTHENTICATION                                   #
    # ###################################################### #
    
    def __basic_authentication(self, username, password):
        
        credentials = b64encode(username.encode(PASSWORD_ENCODING, u'ignore') + u':' + password.encode(PASSWORD_ENCODING, u'ignore'))
        return credentials
        
    ## ################################################################# ##
    
    # ###################################################### #
    # DIGEST AUTHENTICATION                                  #
    # ###################################################### #
    
    def __digest_authentication(self, authHeader, method, path, username, password):
        
        type, space, details = authHeader.partition(u' ')
        
        realm = nonce = opaque = qop = algorithm = None
                
        parameters = details.split(u',')
        for parameter in parameters:
            
            name, eq, value = parameter.partition(u'=')
            if lower(name.strip()) == u'realm':
                realm = value.strip()[1:-1]
            elif lower(name.strip()) == u'nonce':
                nonce = value.strip()[1:-1]
            elif lower(name.strip()) == u'opaque':
                opaque = value.strip()[1:-1]
            elif lower(name.strip()) == u'qop':
                qop = value.strip()[1:-1]
            elif lower(name.strip()) == u'algorithm':
                algorithm = lower(value.strip()[1:-1])
            else:
                pass

        if realm != None and nonce != None:
            # IMPORTANT NOTE: several shortcuts have been used here:
            # 1 - 'algorithm' is assumed to be MD5
            # 2 - Because of backwards compatibility of RFC 2617 with
            #     old RFC 2069, the 'qop' is optional in the client
            #     request. We exploit this to ignore it (and thus
            #     significantly simplify the implementation...)
            
            ha1 = unicode(lower(hashlib.md5(self.__auth_username + u':' + realm + u':' + self.__auth_password).hexdigest()))
            ha2 = unicode(lower(hashlib.md5(upper(method) + u':' + path).hexdigest()))
            response = unicode(lower(hashlib.md5(ha1 + u':' + nonce + u':' + ha2 ).hexdigest()))
            
            r_username = u'username="' + self.__auth_username + u'"'
            r_realm = u'realm="' + realm + u'"'
            r_nonce = u'nonce="' + nonce + u'"'
            r_uri = u'uri="' + path + u'"'
            r_response = u'response="' + response + u'"'
            
            if opaque != None:
                r_opaque =  u',opaque="' + opaque + u'"'
            else:
                r_opaque = u''
            
            credentials = r_username + u',' + r_realm + u',' + r_nonce + u',' + r_uri + u',' + r_response + r_opaque
        
        else:
            credentials = u''
        
        return credentials
    
    ## ################################################################# ##
    
    def __sendRequest(self, httpRequest):
        
        
        # converting the parameters from unicode to network encoding (ASCII)
        
        req_method = httpRequest.get_method().encode(NETWORK_ENCODING, u'ignore')
        req_path = httpRequest.get_path().encode(NETWORK_ENCODING, u'ignore')
        req_headers = {}
        for header, value in httpRequest.get_all_headers().items():
            req_headers[header.encode(NETWORK_ENCODING, u'ignore')] = value.encode(NETWORK_ENCODING, u'ignore')
        if len(httpRequest.get_data()) > 0:
            req_contains_data = True
            req_data = httpRequest.get_data().encode(NETWORK_ENCODING, u'ignore')
        else:
            req_contains_data = False
        
        # Sending of the request
        # Note: the 'host' header is automaticaly set to self.__host (3rd param = False)
        self.__connection.putrequest(req_method, self.__url_prefix + req_path, False, True)
           
            
        for header, value in req_headers.items():
            self.__connection.putheader(header, value)
        self.__connection.endheaders()
        
        if req_contains_data:
            self.__connection.send(req_data)
        
        # Receiving the response
        response = self.__connection.getresponse()
        
        # parsing the response
        httpResponse = self.__parseResponse(response)
        
        
        return httpResponse
    
    ## ################################################################# ##
    
    def __parseResponse(self, response):
        
        global DEFAULT_DECODING, NETWORK_ENCODING
        
        httpResponse = HTTPResponse()
        
        # version extraction
        if response.version == 10:
            httpResponse.set_version(u'1.0')
        elif response.version == 11:
            httpResponse.set_version(u'1.1')
        
        # status code extraction
        httpResponse.set_code(unicode(response.status))
        
        # reason extraction
        httpResponse.set_reason(response.reason.decode(NETWORK_ENCODING, u'ignore'))
        
        # headers extraction
        resp_headers = {}
        for tuple in response.getheaders():
            httpResponse.set_header(tuple[0].decode(NETWORK_ENCODING, u'ignore'), tuple[1].decode(NETWORK_ENCODING, u'ignore'))
        
        # data extraction
        resp_data = response.read()
        
        
        # obtaining the response encoding
        resp_encoding = DEFAULT_DECODING
        
        if httpResponse.get_all_headers().has_key(u'content-type'):
            contentType = httpResponse.get_header(u'content-type')
            if u'charset=' in contentType:
                subs = contentType.split(u';')
                for sub in subs:
                    if u'charset=' in sub:
                        trash, sep, encoding = sub.partition(u'=')
                        if encoding.strip() != u'':
                            resp_encoding = encoding.decode(NETWORK_ENCODING, u'ignore')
                            break
            else:
                pass
        else:
            pass
        
        httpResponse.set_data(resp_data.decode(resp_encoding, u'ignore'))
        
        return httpResponse


## ################################################################# ##
## PUBLIC CLASS: HTTPRequest
## ################################################################# ##
## This class models an HTTP request and is used as a data structure.
## ################################################################# ##

class HTTPRequest(object):
    
    def __init__(self):
        self.__version = u'1.1'
        self.__method = u''
        self.__path = u''
        self.__headers = {} 
        self.__data = u''

    ## ################################################################# ##
    
    def set_version(self, version):
        self.__version = version
    
    ## ################################################################# ##
    
    def get_version(self):
        return self.__version

    ## ##################################################################### ##
    
    def set_method(self, method): 
        self.__method = upper(method)
    
    ## ##################################################################### ##

    def get_method(self):
        return self.__method
    
    ## ##################################################################### ##

    def set_path(self, path, doquote=False):
        
        # WARNING:_____________________________________________________
        # If doquote is set to True, we add '%' to the safe
        # characters of quote to avoid requoting a already quoted path
        # _____________________________________________________________
        
        if doquote:
            # path = unquote(path.encode(BASE_ENCODING)).decode(QUOTE_ENCODING)
            self.__path = quote(path.encode(QUOTE_ENCODING), URL_SAFE_CHARS + '%').decode(BASE_ENCODING)
        else:
            self.__path = path
    
    ## ##################################################################### ##

    def get_path(self, dounquote=False):
        """
        @params:    (void)
        @return:    Unicode string
        """
        
        global QUOTE_ENCODING, BASE_ENCODING
        
        # NOTE:________________________________________________________________ 
        # dounquote is set to False by default because, generally, this
        # method is called to retrieve data before performing an HTTP request.
        # At that moment, we want the path to stay encoded (to be sent over
        # the network in HTTP request). The dounquote parameter should be
        # set to True only if, for some reason the the path has to be retrieved
        # for another purpose than performing the HTTP request...
        # _____________________________________________________________________
        
        if dounquote:
            try:
                return unquote(self.__path.encode(BASE_ENCODING)).decode(QUOTE_ENCODING)
            except UnicodeDecodeError:
                # WARNING: The unquote method seems to have problems on certain cases,
                # with the URL scanner tests (when % is used for other purposes than %XX)
                # leading to errors on further decoding to unicode. For this reason
                # we except UnicodeDecoreErrors and if they occur, we give up unquoting
                
                return self.__path
        else:
            return self.__path

    ## ##################################################################### ##

    def set_header(self, header, value):
        self.__headers[lower(header)] = value
    
    ## ##################################################################### ##

    def get_header(self, header):
        if self.__headers.has_key(lower(header)):
            return self.__headers[lower(header)]
        else:
            return None
    
    ## ##################################################################### ##

    def get_all_headers(self):
        headers = {}
        for header, value in self.__headers.items():
            headers[lower(header)] = value
        return headers
    
    ## ##################################################################### ##

    def set_data(self, data, autoUpdate=True):
        self.__data = data
        
        # If 'autoUpdate' is set to 'True' (by defalt) the
        # 'content-length' header is automatically set to the right value
        if autoUpdate and len(self.__data) > 0:
            self.set_header(u'content-length', unicode(len(self.__data)))
    
    ## ##################################################################### ##

    def get_data(self):
        return self.__data
    

## ################################################################# ##
## PUBLIC CLASS: HTTPRequest
## ################################################################# ##
## This class models an HTTP response and is used as a data structure.
## Beware: Not to be confused with httplib.HTTPResponse !
## ################################################################# ##

class HTTPResponse(object):

    def __init__(self):
        self.__version = u''
        self.__code = u''
        self.__reason = u''
        self.__headers = {}
        self.__data = u''
        self.__charset = u''
    
    ## ##################################################################### ##
    
    def set_version(self, version):
        self.__version = version
    
    ## ##################################################################### ##
    
    def get_version(self):
        return self.__version
    
    ## ##################################################################### ##

    def set_code(self, code):
        self.__code = code
    
    ## ##################################################################### ##

    def get_code(self):
        return self.__code
    
    ## ##################################################################### ##

    def set_reason(self, reason):
        self.__reason = reason
    
    ## ##################################################################### ##

    def get_reason(self):
        return self.__reason
    
    ## ##################################################################### ##

    def set_header(self, header, value):
        self.__headers[lower(header.strip())] = value.strip()
    
    ## ##################################################################### ##

    def get_header(self, header):
        if self.__headers.has_key(lower(header)):
            return self.__headers[lower(header.strip())]
        else:
            return None
    
    ## ##################################################################### ##

    def get_all_headers(self):
        headers = {}
        for header, value in self.__headers.items():
            headers[lower(header)] = value
        return headers
    
    ## ##################################################################### ##

    def set_data(self, data):
        self.__data = data
    
    ## ##################################################################### ##
    
    def get_data(self):
        return self.__data
    