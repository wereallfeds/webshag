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
import urlparse
from threading import Thread
from string import letters, digits
from string import lower, hexdigits
from random import choice

from webshag.core import core_file, core_http, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##
NOT_FOUND = [u'404']
REDIRECTION = [u'301', u'302', u'303', u'307']
UNAUTHORIZED = [u'401']
FORBIDDEN = [u'403']
SERVER_ERROR = [u'500']
MISS_DISPLAY_RATE = 5

## ################################################################# ##
## CLI OUTPUT FUNCTIONS
## ################################################################# ##
## The possible result configurations issued by this module are:
## Generic error:               {ERROR}
## Error on a single target:    {HOST, PORT, IPADDRESS, ERROR}
## Target specification:        {HOST, PORT, IPADDRESS, TARGET}
## Info relative to target:     {HOST, PORT, IPADDRESS, INFO}
## Web server detection:        {HOST, PORT, IPADDRESS, SERVER, BANNER}
## URL scanner hit:             {HOST, PORT, IPADDRESS, PATH, CODE,
##                               REDIRECTION, DESCRIPTION, TRIGGER}
##
## URL Scanner Miss:            {HOST, PORT, IPADDRESS, MISS}
## ################################################################# ##

def cli_output_result(result):
    
    if result.has_key(u'ERROR'):
        print '\n% ERROR %\t' + result[u'ERROR'] + u'!'
    
    elif result.has_key(u'TARGET'):
        print ''
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        print result[u'TARGET']
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        
    elif result.has_key(u'INFO'):
        print '\n% INFO %\t' + result[u'INFO']
        
    elif result.has_key(u'SERVER'):
        print '\n% BANNER %\t' + result[u'BANNER'] + u' => ' + result[u'SERVER']
    
    elif result.has_key(u'MISS'):
        pass
        
    else:
        print '\n% ' + result[u'CODE'] +'  %\t' + result[u'PATH']
        print '% DESC %\t' + result[u'DESCRIPTION']

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##
## The functions below are used to INTERFACE this module with upper
## layers. As long as these functions exist (and have the same input
## and output parameters) all the rest of the module can be modified
## without interfering with upper levels using it.
## ################################################################# ##

def perform(hosts, ports, roots, server, skip_string, cli, results, results_lock, switch, switch_lock):
    
# Input:  hosts - [unicode] - list of target hosts or IP addresses
#         ports - [integer] - list of target ports
#         roots - [unicode] - list of root directories
#         server - unicode - force this as the web server
#         skip_string - unicode - user-defined false positive indicator
#         cli - boolean - set verbosity on STDOUT to ON/OFF
#         results - [dict] - (shared) output results list
#         results_lock - threading.Lock - (shared) lock on the output list
#         switch - [boolean] - (shared) switch controlling scan life-cycle (ON/OFF)
#         switch_lock - threading.Lock - (shared) lock on switch
#
# Return: (void)
#
# This function performs a URL scan of on target hosts/ports based on test files. The results
# are appended to the (shared) results list provided as parameter. The scan ends when all
# the applicable entries in the test list(s) lists have been processed or as soon as the (shared)
# switch is 'turned off' (i.e. switch = [False]) by the calling instance (e.g. GUI/CLI).
    
    try:
        
        # loading the list of known webserver banners from database file
        known_banners = core_file.db_load_known_banners()
        
        # Loading and checking the config parameters
        cfParser = core_file.cfg_start_get()
        use_db_nikto = core_file.cfg_get_use_db_nikto(cfParser)
        use_db_custom = core_file.cfg_get_use_db_custom(cfParser)
        threads = core_file.cfg_get_scan_threads(cfParser)
        scan_show_codes_str = core_file.cfg_get_scan_show_codes(core_file.cfg_start_get())
        core_file.cfg_end_get(cfParser)
        
        if not core_utilities.check_threads(threads) or not core_utilities.check_http_codes(scan_show_codes_str):
            
            issue_result(results, results_lock, cli, {u'ERROR': u'Invalid configuration settings.'})
        
        else:
            
            # Nikto tests can be loaded here as they are not dependent on the target
            # they are thus only loaded once (minimizing file access)
            if use_db_nikto:
                nikto_tests = core_file.db_load_nikto_tests()
            
            scan_show_codes = [c.strip() for c in scan_show_codes_str.split(u',')]
            
            hosts_done = []
            
            for host in hosts:
                
                with switch_lock:
                    
                    on = switch[0]
                    
                if not on:
                    break
                
                else:
                    
                    if host in hosts_done:
                        continue
                    else:
                        hosts_done.append(host)
                    
                    ports_done = []
                    ipaddress = core_utilities.get_ip_address(host)
                    
                    for port in ports:
                        
                        with switch_lock:
                            on = switch[0]
                            
                        if not on:
                            break
                        
                        else:
                            
                            if port in ports_done:
                                continue
                            else:
                                ports_done.append(port)
                            
                            issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'TARGET': host + u' / ' + unicode(port)})
                            
                            # test if target is up and valid...
                            http_test = core_http.test_http(host, port)
                            
                            if not http_test[0]:
                                error_message = http_test[1]
                                
                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': error_message})
                                
                                continue
                                # if the host/port is not valid, skip to next port or next host
                            
                            else: # host/port respond to http
                            
                                # indentify server
                                httpClient = core_http.HTTPClient(host, port)
                                
                                request_404 = core_http.HTTPRequest()
                                request_404.set_method(u'GET')
                                request_404.set_path(u'/' + u''.join([choice(letters + digits) for i in range(8)]))
                                response_404 = httpClient.perform_request(request_404)
                                
                                if response_404 == None:
                                    issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': u'HTTP Request to server failed. Scan aborted.'})
                                    
                                    continue
                                    # if these request does not work, the following tests will cause trouble,
                                    # thus consider that host/port is not valid...
                                    
                                else:
                                    
                                    server_known, server_banner, server_id = __identify_server(response_404, known_banners)
                                    
                                    # if the user wants to force the server
                                    if server != u'' and server in known_banners.values():
                                        server_id = server
                                        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'SERVER': server_id + ' *FORCED', u'BANNER': server_banner})
                                    else:
                                        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'SERVER': server_id, u'BANNER': server_banner})
                                    
                                    # loading the tests from database
                                    tests_original = []
                                    
                                    if use_db_nikto:
                                        tests_original.extend(nikto_tests)
                                        
                                    if use_db_custom:
                                        tests_original.extend(core_file.db_load_custom_tests([], host, True))

                                    roots_done = []
                                    for root in roots:
                                        
                                        with switch_lock:
                                            on = switch[0]
                                            
                                        if not on:
                                            break
                                        
                                        else:
                                        
                                            if root in roots_done:
                                                continue
                                            else:
                                                roots_done.append(root)
                                        
                                            # fingerprint interesting messages
                                            # root
                                            request_root = core_http.HTTPRequest()
                                            request_root.set_method(u'GET')
                                            request_root.set_path(root)
                                            response_root = httpClient.perform_request(request_root)
                                            # index.php
                                            request_indexphp = core_http.HTTPRequest()
                                            request_indexphp.set_method(u'GET')
                                            request_indexphp.set_path(root + u'index.php')
                                            response_indexphp = httpClient.perform_request(request_indexphp)
                                            # 404 message - or should be
                                            request_404 = core_http.HTTPRequest()
                                            request_404.set_method(u'GET')
                                            request_404.set_path(root + u''.join([choice(letters + digits) for i in range(8)]))
                                            response_404 = httpClient.perform_request(request_404)
                                            
                                            fingerprints = {}
                                            
                                            fingerprints[u'root'] = core_http.fingerprint_response(request_root, response_root)
                                            if fingerprints[u'root'] == None:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': u'FP(' + request_root.get_path() + ') => failure!'})
                                            else:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': u'FP(' + request_root.get_path() + ') => ' + str(fingerprints[u'root'][0]) + u'#' + str(fingerprints[u'root'][1]) + u'#' + str(fingerprints[u'root'][2]) + u'#' + str(fingerprints[u'root'][3])})
                                               
                                            fingerprints[u'error404'] = core_http.fingerprint_response(request_404, response_404)
                                            if fingerprints[u'error404'] == None:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': u'FP(' + request_404.get_path() + ') => failure!'})
                                            else:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': u'FP(' + request_404.get_path() + ') => ' + str(fingerprints[u'error404'][0]) + u'#' + str(fingerprints[u'error404'][1]) + u'#' + str(fingerprints[u'error404'][2]) + u'#' + str(fingerprints[u'error404'][3])})
                                               
                                            fingerprints[u'index.php'] = core_http.fingerprint_response(request_indexphp, response_indexphp)
                                            if fingerprints[u'index.php'] == None:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': u'FP(' + request_indexphp.get_path() + ') => failure!'})
                                            else:
                                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': u'FP(' + request_indexphp.get_path() + ') => ' + str(fingerprints[u'index.php'][0]) + u'#' + str(fingerprints[u'index.php'][1]) + u'#' + str(fingerprints[u'index.php'][2]) + u'#' + str(fingerprints[u'index.php'][3])})
                                            
                                            
                                            # robots.txt
                                            request_robots = core_http.HTTPRequest()
                                            request_robots.set_method(u'GET')
                                            request_robots.set_path(root + u'robots.txt')
                                            response_robots = httpClient.perform_request(request_robots)
                                            
                                            if response_robots.get_code() == u'200':
                                                robots_fingerprint = core_http.fingerprint_response(request_robots, response_robots)
                                                if not core_http.test_response_fingerprint(robots_fingerprint, fingerprints[u'root']) and not core_http.test_response_fingerprint(robots_fingerprint, fingerprints[u'error404']) and not core_http.test_response_fingerprint(robots_fingerprint, fingerprints[u'index.php']):
                                                    issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': root + u'robots.txt found. It might be interesting to have a look inside.'})
                                            
                                            tests = tests_original[:]
                                            used_triggers = []
                                            triggers = [server_id]
                                            
                                            while len(triggers) > 0:
                                                
                                                with switch_lock:
                                                    on = switch[0]
                                                    
                                                if not on:
                                                    break
                                                else:
                                                    
                                                    if use_db_custom:
                                                        tests.extend(core_file.db_load_custom_tests(triggers, host, False))
                                                    
                                                    used_triggers.extend(triggers)
                                                    triggers = []
                                                    
                                                    running = []
                                                    for i in range(0, threads):
                                                        scan_thread = ScanThread(host, port, ipaddress, root, fingerprints, tests, triggers, skip_string, scan_show_codes, cli, results, results_lock, switch, switch_lock)
                                                        scan_thread.start()
                                                        running.append(scan_thread)
                                                    for thread in running:
                                                        thread.join()
                                                        
                                                    for trigger in triggers:
                                                        if trigger in used_triggers:
                                                            triggers.remove(trigger)
    except core_error.Config_Error, e:
        issue_result(results, results_lock, cli, {u'ERROR': e.error_message})

## ################################################################# ##
## PRIVATE FUNCTIONS
## ################################################################# ##
## These are internal functions. The are only called from inside
## this module and cannot (should not) be accessed from outside.
## ################################################################# ##

def issue_result(results, results_lock, cli, result):
    with results_lock:
        results.append(result)
        if cli:
            cli_output_result(result)

## ################################################################# ##

def __identify_server(httpResponse, known_banners):
    
    server = []
    
    # voting confidence ratings #
    vote_banner = 2
    vote_body = 1
    
    # header banner grabbing #
    banner = u''
    if httpResponse.get_header(u'server') != None:
        banner = httpResponse.get_header(u'server')
        for (bnr, srv) in known_banners.items():
            if bnr.match(banner):
                for i in range(0, vote_banner):
                    server.append(srv)
                break

    # search for server in 404 body #
    body = lower(httpResponse.get_data())
    for (bnr, srv) in known_banners.items():
        if bnr.search(body):
            for i in range(0, vote_body):
                server.append(srv)
    
    # decision #
    if len(server) == 0:
        if banner != u'':
            return (False, banner, u'unknown')
        else:
            return (False, u'no banner', u'unknown')
    else:
        maj_server = 0
        maj_votes = 0
        for vote in server:
            count = server.count(vote)
            if count > maj_votes:
                maj_server = vote
                maj_votes = count
        
        return (True, banner, maj_server)


## ################################################################# ##
## INTERNAL CLASS: ScanThread
## ################################################################# ##
## This class implements the thread used to perform URL scans.
## The threads share a list of entries to test (loaded from db files).
## While there are entries left, a thread picks the next unprocessed
## entry, uses it to issue an HTTP request and tests if the result is
## a hit or not. In case of hit, the result is appended to the (shared)
## results list.
## ################################################################# ##

class ScanThread(Thread):
    
    def __init__(self, host, port, ipaddress, root, fingerprints, tests, triggers, skip_string, scan_show_codes, cli, results, results_lock, switch, switch_lock):
        
        Thread.__init__(self)
        
        self.__host = host
        self.__port = port
        
        if root.strip() == u'/':
            self.__root = u''
        else:
            self.__root = root[:-1]
            
        self.__fingerprints = fingerprints
        self.__tests = tests
        self.__triggers = triggers
        self.__skip_string = skip_string
        self.__scan_show_codes = scan_show_codes
        self.__cli = cli
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        
        self.__counter = 0
        
        self.__ipaddress = ipaddress
        
        self.__httpClient = core_http.HTTPClient(self.__host, self.__port)
    
    ## ################################################################# ##
    
    def run(self):
        
        while True:
            
            with self.__switch_lock:
                on = self.__switch[0]
            
            if not on:
                break
            
            else:
                
                try:
                    
                    test = self.__tests.pop(0)
                    #  OSVDB | SERVER | METHOD | PATH | HEADER | DATA | MATCH_CODE | MATCH | MATCH_AND | MATCH_OR | FAIL_CODE | FAIL | FAIL_OR | DESCRIPTION | TRIGGER
                    
                    request = core_http.HTTPRequest()
                    request.set_method(test[u'METHOD'])
                    request.set_path(self.__root + test[u'PATH'], False)
                    if test[u'DATA'] != u'':
                        request.set_data(test[u'DATA'])
                    if test[u'HEADER'] != u'':
                        request.set_header(test[u'HEADER'].split(u':')[0].strip(), test[u'HEADER'].split(u':')[1].strip())
                    # Note: the header provided in the databse entry is set at last in order to
                    # overwrite a previously set default header
                    
                    response = self.__httpClient.perform_request(request)
                    
                    if response != None:
                        
                        result = self.__test_hit(test, request, response)
                        
                        if result != None:
                            
                            issue_result(self.__results, self.__results_lock, self.__cli, result)
                            
                            
                            if result.has_key(u'TRIGGER') and result[u'TRIGGER'] != u'':
                                self.__triggers.append(result[u'TRIGGER'])
                                
                        else:
                            if self.__counter % MISS_DISPLAY_RATE == 0:
                                    issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': request.get_path(True)})
                            continue
                    else:
                        issue_result(self.__results, self.__results_lock, self.__cli, {u'ERROR': u'Request failed. Server may be overloaded.'})
                        continue
                    
                except IndexError:
                    break
        
    ## ################################################################# ##
    
    def __test_hit(self, test, request, response):
        
        # this method is in charge of applying the hit detection algorithm
        
        #response_data = response.get_data().lower()
        response_data = response.get_data()
        response_code = response.get_code()
        
        # ####################################
        # STEP 1: simple non matching results
        # ####################################
        
        # 1.1 - if the response is a '404 Not Found'
        if response_code in NOT_FOUND:
            
            return None
        
        # 1.2 - if the response code corresponds to the 'fail code'
        if test[u'FAIL_CODE'] != u'' and test[u'FAIL_CODE'] == response_code:
                
            return None
        
        # 1.3 - if the response contains the 'fail' inidicating string(s)
        if ((test[u'FAIL'] != u'') and (test[u'FAIL'] in response_data)) or ((test[u'FAIL_OR'] != u'') and (test[u'FAIL_OR'] in response_data)):
                
            return None
        
        # 1.4 - if the response data contains the user-defined skip string
        if self.__skip_string.strip() != u'' and self.__skip_string in response_data:
            
            return None
        
        # 1.5 - ignore all the result codes that are not explicitely
        # required by the user in the configuration file
        if response_code not in self.__scan_show_codes:
            
            return None
        
        # ####################################
        # STEP 2: potential false positives
        # ####################################
        
        # fingerptinting the response
        fingerprint = core_http.fingerprint_response(request, response)
        
        # 2.1 - if fingerprints mathces the supposed '404 Not Found'fingerprint
        if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'error404']):
            
            return None
        
        # 2.2 - if the page is identical to the root page
        if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'root']):
            
            return None

        # 2.3 - if the path contains index.php and the page is
        # exactly the same as the /index.php page
        # (this is useful for /index.php?lots_of_useless_params)
        # Note that this idea has been inspired by *** Nikto 2 ***
        if u'/index.php' in request.get_path():
            if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'index.php'], False):
                
                return None
            
        
        # ####################################
        # STEP 3: Real matches
        # ####################################
       
        if (test[u'MATCH_CODE'] != u'' and test[u'MATCH_CODE'] == response_code):
            
            #match = test[u'MATCH'].lower()
            #match_or = test[u'MATCH_OR'].lower()
            #match_and = test[u'MATCH_AND'].lower()
            
            match = test[u'MATCH']
            match_or = test[u'MATCH_OR']
            match_and = test[u'MATCH_AND']
            
            if ((match in response_data) or (match_or in response_data)) and (match_and in response_data):
                # note that ( ''(empty string) in text ) is true for any text, thus empty fields don't hurt... 
                
                result = {}
                result[u'HOST'] = self.__host
                result[u'PORT'] = unicode(self.__port)
                result[u'IPADDRESS'] = self.__ipaddress
                result[u'PATH'] = request.get_path()
                result[u'CODE'] = response.get_code()
                result[u'REDIRECTION'] = u''
                result[u'DESCRIPTION'] = test[u'DESCRIPTION']
                result[u'TRIGGER'] = test[u'TRIGGER']
                return result
            
            else:
                
                return None
            
        
        if test[u'MATCH_CODE'] == u'' and response_code == u'200':
            
            #match = test[u'MATCH'].lower()
            #match_or = test[u'MATCH_OR'].lower()
            #match_and = test[u'MATCH_AND'].lower()
            
            match = test[u'MATCH']
            match_or = test[u'MATCH_OR']
            match_and = test[u'MATCH_AND']
            
            # beware of cases where Nikto's match has been moved to match_code !!!!
            if ((match != u'' and match in response_data) or (match_or != u'' and match_or in response_data)) and (match_and == u'' or (match_and != u'' and match_and in response_data)):
                result = {}
                result[u'HOST'] = self.__host
                result[u'PORT'] = unicode(self.__port)
                result[u'IPADDRESS'] = self.__ipaddress
                result[u'PATH'] = request.get_path()
                result[u'CODE'] = response.get_code()
                result[u'REDIRECTION'] = u''
                result[u'DESCRIPTION'] = test[u'DESCRIPTION']
                result[u'TRIGGER'] = test[u'TRIGGER']
                return result
            
            else:
                
                return None
        
        # ####################################
        # STEP 4: Other interesting results
        # ####################################
        
        # 4.1 - Notify redirections
        if response_code in REDIRECTION:
            
            result = {}
            result[u'HOST'] = self.__host
            result[u'PORT'] = unicode(self.__port)
            result[u'IPADDRESS'] = self.__ipaddress
            result[u'PATH'] = request.get_path()
            result[u'CODE'] = response.get_code()
            
            if response.get_header(u'location') != None:
                location = response.get_header(u'location')
            else:
                location = u'unknown location'
                
            result[u'REDIRECTION'] = location
            result[u'DESCRIPTION'] = u'Redirected to: ' + location
            result[u'TRIGGER'] = u''
            return result
        
        # 4.2 - Notify unauthorized
        if response_code in UNAUTHORIZED:
            result = {}
            result[u'HOST'] = self.__host
            result[u'PORT'] = unicode(self.__port)
            result[u'IPADDRESS'] = self.__ipaddress
            result[u'PATH'] = request.get_path()
            result[u'CODE'] = response.get_code()
            result[u'REDIRECTION'] = u''
            result[u'DESCRIPTION'] = u'Unauthorized access'
            result[u'TRIGGER'] = test[u'TRIGGER']
            return result
        
        # 4.3 - Notify forbidden
        if response_code in FORBIDDEN:
            result = {}
            result[u'HOST'] = self.__host
            result[u'PORT'] = unicode(self.__port)
            result[u'IPADDRESS'] = self.__ipaddress
            result[u'PATH'] = request.get_path()
            result[u'CODE'] = response.get_code()
            result[u'REDIRECTION'] = u''
            result[u'DESCRIPTION'] = u'Forbidden access'
            result[u'TRIGGER'] = u''
            return result
        
        # 4.4 - Notify error
        if response_code in SERVER_ERROR:
            result = {}
            result[u'HOST'] = self.__host
            result[u'PORT'] = unicode(self.__port)
            result[u'IPADDRESS'] = self.__ipaddress
            result[u'PATH'] = request.get_path()
            result[u'CODE'] = response.get_code()
            result[u'REDIRECTION'] = u''
            result[u'DESCRIPTION'] = u'Caused a server internal error.'
            result[u'TRIGGER'] = u''
            return result
       
        # default if no other applies...
        return None
