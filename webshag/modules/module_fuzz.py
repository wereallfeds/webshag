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
import re
import urlparse
import threading
from string import letters, digits
from string import lower, hexdigits
from random import choice

from webshag.core import core_file, core_http, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

GENERATOR_VARIABLE_REGEXP = re.compile(r'(?P<var>\[[azAZ\d-]+\]\{[0-9]+\})', re.IGNORECASE)
MISS_DISPLAY_RATE = 5

## ################################################################# ##
## CLI OUTPUT FUNCTIONS
## ################################################################# ##
## The possible result configurations issued by this module are:
##
## Generic error:               {ERROR}
## Error on a single target:    {HOST, PORT, IPADDRESS, ERROR}
## Target specification:        {HOST, PORT, IPADDRESS, TARGET}
## Generic information:         {HOST, PORT, IPADDRESS, INFO}
## Fuzzer match:                {HOST, PORT, IPADDRESS, PATH, CODE}
## Fuzzer Miss:                 {HOST, PORT, IPADDRESS, MISS}
## ################################################################# ##

def cli_output_result(result):
    
    if result.has_key(u'ERROR'):
        print '\n% ERROR % ' + result[u'ERROR']
    
    elif result.has_key(u'INFO'):
        print '\n% INFO % ' + result[u'INFO']
        
    elif result.has_key(u'TARGET'):
        print ''
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        print result[u'TARGET']
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
    
    elif result.has_key(u'MISS'):
        pass
        
    else:
        print '\n% ' + result[u'CODE'] + ' %  '  + result[u'PATH']


## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##
## The functions below are used to INTERFACE this module with upper
## layers. As long as these functions exist (and have the same input
## and output parameters) all the rest of the module can be modified
## without interfering with upper levels using it.
## ################################################################# ##

def perform(hosts, ports, roots, mode, modecpl, cli, results, results_lock, switch, switch_lock):
    
# Input:  hosts - [unicode] - list of target hosts or IP addresses
#         ports - [integer] - list of target ports
#         roots - [unicode] - list of root directories
#         mode - integer - 0 = listmode, 1 = filemode
#         modecpl - unicode - recursive (list mode) or filename generator (gen mode)
#         cli - boolean - set verbosity on STDOUT to ON/OFF
#        
#         results - [dict] - (shared) output results list
#         results_lock - threading.Lock - (shared) lock on the output list
#         switch - [boolean] - (shared) switch controlling scan life-cycle (ON/OFF)
#         switch_lock - threading.Lock - (shared) lock on switch
#
# Return: (void)
#
# This function performs a fuzzing scan on target hosts/ports. The encountered results
# are appended to the (shared) results list provided as parameter. The scan ends when all
# the entries in the fuzzing list(s) have been processed or as soon as the (shared)
# switch is 'turned off' (i.e. switch = [False]) by the calling instance (e.g. GUI/CLI).
# Note that fuzzing lists can be read from file (list mode) or generated on the fly
# (generator mode) using a user defined expression.
    
    try:
        # load parameters from config file and test them
        # if some parameter is not valid, issue an 'error' result
        threads = core_file.cfg_get_fuzz_threads(core_file.cfg_start_get())
        fuzz_show_codes_str = core_file.cfg_get_fuzz_show_codes(core_file.cfg_start_get())
        fuzz_method = core_file.cfg_get_fuzz_method(core_file.cfg_start_get())
    
        if not core_utilities.check_threads(threads) or not core_utilities.check_http_codes(fuzz_show_codes_str) or not core_utilities.check_http_method(fuzz_method, True):
            
            result = {u'ERROR': u'Invalid configuration settings.'}
            issue_result(results, results_lock, cli, result)
            
        else:
            
            fuzz_show_codes = [c.strip() for c in fuzz_show_codes_str.split(u',')]
            
            hosts_done = []
            
            for host in hosts:
                
                # check if switch is still 'ON'
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
                        
                        # check if switch is still 'ON'
                        with switch_lock:
                            on = switch[0]
                        if not on:
                            break
                        else:
                            
                            if port in ports_done:
                                continue
                            else:
                                ports_done.append(port)
                            
                            # this 'informative' result is only for display of the new target on GUI/CLI
                            result = {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'TARGET': host + ' / ' + unicode(port)}
                            issue_result(results, results_lock, cli, result)
                            
                            # test if target is up and valid...
                            http_test = core_http.test_http(host, port, fuzz_method)
                            if not http_test[0]:
                                error_message = http_test[1]
                                
                                # if target is down output an 'error' result
                                result = {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': error_message}
                                issue_result(results, results_lock, cli, result)
                                
                                # if the host/port is not valid, go to next port or next host
                                continue 
                            
                            else: # if the target responds to HTTP, go on...
                                
                                httpClient = core_http.HTTPClient(host, port)
                                
                                roots_done = []
                                for root in roots:
                                    
                                    # check if switch is still 'ON'
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
                                        
                                        
                                        
                                        if mode == 0:
                                            
                                            with switch_lock:
                                                on = switch[0]
                                            if not on:
                                                break
                                            else:
                                                
                                                if modecpl[0] == u'1':
                                                
                                                    directories = __find_directories(host, port, ipaddress, root, fingerprints, fuzz_method, threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock)
                                                else:
                                                    directories = []
                                                    
                                            with switch_lock:
                                                on = switch[0]
                                            if not on:
                                                break
                                            else:
                                                
                                                if modecpl[1] == u'1':
                                                    __find_files(host, port, ipaddress, root, fingerprints, fuzz_method, threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock, directories)
                                            
                                        else:
                                            
                                            with switch_lock:
                                                on = switch[0]
                                            if not on:
                                                break
                                            else:
                                                __find_generator(host, port, ipaddress, root, fingerprints, fuzz_method, modecpl.strip(), threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock)
                                            
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

def __find_directories(host, port, ipaddress, root, fingerprints, fuzz_method, threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock):
    
    directories = []
    # retrieving the directory list from file #
    entries = core_file.db_load_fuzzer_dirs()
    
    if len(entries) > 0:
        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': str(len(entries)) + u' entries loaded from directory list.'})
        running = []
        
        # spawn the fuzzing threads #
        for threadNumber in range(0, threads):
            fuzzThread = FuzzThread(host, port, ipaddress, root, fingerprints, fuzz_method, None, fuzz_show_codes[:], cli, entries, directories, results, results_lock, switch, switch_lock)
            fuzzThread.start()
            running.append(fuzzThread)
            
        for thread in running:
            thread.join()
    else:
        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': u'Directory list missing or empty.'})
    
    return directories

## ################################################################# ##

def __find_files(host, port, ipaddress, root, fingerprints, fuzz_method, threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock, directories):

    # retrieving the file list from file #
    entriesSource = core_file.db_load_fuzzer_files()
    extensions = core_file.db_load_fuzzer_extensions()
    
    found_dirs = [root]
    found_dirs.extend(directories)
    
    if len(entriesSource) > 0:
        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': str(len(entriesSource)) + u' entries loaded from file list'})
        
        # search for files in root directory and in
        # all the previously discovered directories
        for directory in found_dirs:
            
            with switch_lock:
                on = switch[0]
            
            # if switch is still ON, go on with next directory...
            if on:
                    entries = entriesSource[:]
                    running = []
                    
                    # spawn the fuzzing threads #
                    for threadNumber in range(0, threads):
                        fuzzThread = FuzzThread(host, port, ipaddress, directory, fingerprints, fuzz_method, extensions[:], fuzz_show_codes[:], cli, entries, [], results, results_lock, switch, switch_lock)
                        fuzzThread.start()
                        running.append(fuzzThread)
                    
                    # wait for the threads to finish #
                    for thread in running:
                        thread.join()
            
            # if switch is OFF, stop...
            else:
                break
    else:
        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': u'File list missing or empty'})

## ################################################################# ##

def __find_generator(host, port, ipaddress, root, fingerprints, fuzz_method, generator, threads, fuzz_show_codes, cli, results, results_lock, switch, switch_lock):
    
    # generate entries from the generator string
    entries = __expand_generator(generator)
    
    if len(entries) > 0:
        issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INFO': str(len(entries)) + u' entries generated'})
        running = []
        
        # spawn the fuzzing threads #
        for threadNumber in range(0, threads):
            fuzzThread = FuzzThread(host, port, ipaddress, root, fingerprints, fuzz_method, [''], fuzz_show_codes[:], cli, entries, [], results, results_lock, switch, switch_lock)
            fuzzThread.start()
            running.append(fuzzThread)
            
        for thread in running:
            thread.join()
    else:
        pass

## ################################################################# ##

def __expand_generator(generator):
    
    # This fucntion 'expands' a generator string in a list of
    # file/directory names to be tested by the fuzzer. The generator
    # is a string containing (fixed) characters and generator patterns
    # that are interpreted to generate variable characters.
    #
    # The generator patterns are of the form: [charset]{X}
    # where the charset refers to one of the allowed sets of
    # characters (a-z, A-Z, a-Z, 0-9) and X is the number
    # of characters to expand.
    #
    # Example: [a-z]{2} = aa, ab, ac, ad, ..., zy, zz
    
    num = u'0123456789'
    alpha_min = u'abcdefghijklmnopqrstuvwxyz'
    alpha_maj = u'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alpha = u'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    
    # first, we find all the generator patterns that are to be
    # expanded and build the corresponding charsets
    expansion_dict = {}
    raw_variables = GENERATOR_VARIABLE_REGEXP.findall(generator)
    
    for raw_var in raw_variables:
        
        if expansion_dict.has_key(raw_var):
            continue
        else:
            
            set = raw_var.split(u']')[0][1:]
            repeat = int(raw_var.split(u'{')[1][:-1])
            
            if set == u'a-z':
                expansion_dict[raw_var] = __sub_expand(alpha_min, repeat)
                
            elif set == u'A-Z':
                expansion_dict[raw_var] = __sub_expand(alpha_maj, repeat)
                
            elif set == u'a-Z':
                expansion_dict[raw_var] = __sub_expand(alpha_min + alpha_maj, repeat)
                
            elif set == u'0-9':
                expansion_dict[raw_var] = __sub_expand(num, repeat)
                
            else:
                continue
    
    # Parsing the genarator string and expanding it
    expansion = [u'']
    generator_split = GENERATOR_VARIABLE_REGEXP.split(generator)

    for sub in generator_split:
        # if the generator pattern refers to an allowed charset, it is
        # expanded by all the values of this charset
        if expansion_dict.has_key(sub):
            
            new_expansion = [old + new for old in expansion for new in expansion_dict[sub]]
            
        else:
            # if the pattern does not refer to an allowed charset it is simply
            # taken 'as-is', i.e as a simple string that is not expanded
            new_expansion = [old + sub for old in expansion]
        
        expansion = new_expansion
        
    return expansion

## ################################################################# ##
    
def __sub_expand(charset, rep):

    seed = [u'']
    for i in range(0, rep):
        seed.extend([s + a for s in seed for a in charset])
        seed = [s for s in seed if len(s) > i]
        
    return seed


## ################################################################# ##
## INTERNAL CLASS: FuzzThread
## ################################################################# ##
## This class implements the thread used to fuzz directories and files.
## The threads share a list of entries to test (files or directories).
## While there are entries left, a thread picks the next unprocessed
## entry, uses it to issue an HTTP request and tests if the result is
## a hit or not. In case of hit, the result is appended to the (shared)
## results list.
## ################################################################# ##

class FuzzThread(threading.Thread):
    
    def __init__(self, host, port, ipaddress, root, fingerprints, fuzz_method, extensions, fuzz_show_codes, cli, entries, internal_results, results, results_lock, switch, switch_lock):

        threading.Thread.__init__(self)
        
        self.__host = host
        self.__port = port
        self.__root = root 
        self.__entries = entries
        self.__extensions = extensions
        self.__cli = cli
        self.__fuzz_show_codes = fuzz_show_codes
        self.__fuzz_method = fuzz_method
        self.__internal_results = internal_results
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        self.__ipaddress = ipaddress
        self.__fingerprints = fingerprints
        
        self.__counter = 0
        
        # creating an instance of HTTPClient #
        self.__httpClient = core_http.HTTPClient(self.__host, self.__port)
        
    ## ################################################################# ##
    
    def run(self):
        
        # Loop until there are no more entries
        # left in the list (shared among threads)
        while True:
            
            with self.__switch_lock:
                on = self.__switch[0]
                
            # if switch is OFF, give up...
            if not on:
                break
            
            # if switch is still ON, go on with next entry...
            else:
                try:
                    # pop the next entry from the (shared list)
                    # note that pop() is an atomic operation
                    # and is thus assumed to be thread-safe
                    entry = self.__entries.pop(0)
                    
                    # directory mode
                    if self.__extensions == None:
                        
                        req = core_http.HTTPRequest()
                        req.set_method(self.__fuzz_method)
                        req.set_path(self.__root + entry + u'/', True)
                        
                        # peform the request through the HTTP client
                        resp = self.__httpClient.perform_request(req)
                        
                        if resp != None:
                            
                            self.__counter += 1
                            code = resp.get_code()
                            
                            if code in self.__fuzz_show_codes:
                                
                                fingerprint = core_http.fingerprint_response(req, resp)
                                
                                if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'error404']):
                                    
                                    if self.__counter % MISS_DISPLAY_RATE == 0:
                                        issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                    continue
                                
                                if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'root']):
                                    
                                    if self.__counter % MISS_DISPLAY_RATE == 0:
                                        issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                    continue
                                
                                result = {u'HOST': self.__host, u'PORT': unicode(str(self.__port)), u'IPADDRESS': self.__ipaddress, u'PATH': req.get_path(True), u'CODE': resp.get_code()}
                                # if the response indicates a hit, append
                                # this result to the results list.
                                issue_result(self.__results, self.__results_lock, self.__cli, result)
    
                                # whe  n a directory is found, it is appended to the
                                # (internal) list of directories (used as roots to
                                # fuzz files)
                                self.__internal_results.append(result[u'PATH'])
                                
                            else:
                                
                                if self.__counter % MISS_DISPLAY_RATE == 0:
                                        issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                continue
                        else:
                            issue_result(self.__results, self.__results_lock, self.__cli, {u'ERROR': u'Request failed. Server may be overloaded.'})
                            continue
                    
                    # file mode
                    else:
                        for extension in self.__extensions:
                            
                            with self.__switch_lock:
                                on = self.__switch[0]
                    
                            # if switch is OFF, give up...
                            if not on:
                                break
                    
                            # if switch is still ON, go on with next entry...
                            else:
                            
                                # create a new HTTP request from the entry
                                req = core_http.HTTPRequest()
                                req.set_method(self.__fuzz_method)
                                req.set_path(self.__root + entry + extension, True)
                                
                                # peform the request through the HTTP client
                                resp = self.__httpClient.perform_request(req)
                                
                                if resp != None:
                                    
                                    self.__counter += 1
                                    code = resp.get_code()
                                    
                                    if code in self.__fuzz_show_codes:
                                        
                                        fingerprint = core_http.fingerprint_response(req, resp)
                                        
                                        if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'error404']):
                                            
                                            if self.__counter % MISS_DISPLAY_RATE == 0:
                                                issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                            continue
                                        
                                        if core_http.test_response_fingerprint(fingerprint, self.__fingerprints[u'root']):
                                            
                                            if self.__counter % MISS_DISPLAY_RATE == 0:
                                                issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                            continue
                                        
                                        result = {u'HOST': self.__host, u'PORT': unicode(str(self.__port)), u'IPADDRESS': self.__ipaddress, u'PATH': req.get_path(True), u'CODE': resp.get_code()}
                                        # if the response indicates a hit, append
                                        # this result to the results list.
                                        issue_result(self.__results, self.__results_lock, self.__cli, result)
                                        
                                    else:
                                        
                                        if self.__counter % MISS_DISPLAY_RATE == 0:
                                                issue_result(self.__results, self.__results_lock, self.__cli, {u'MISS': req.get_path(True)})
                                        continue
                                else:
                                    issue_result(self.__results, self.__results_lock, self.__cli, {u'ERROR': u'Request failed. Server may be overloaded.'})
                                    continue
                        
                except IndexError:
                    break
    
    ## ################################################################# ##