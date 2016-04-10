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
import re
import threading
import urlparse
from os.path import dirname
from string import lower
from time import sleep
from webshag.core import core_http, core_file, core_utilities, core_error

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

MAX_LINKS = 1000
THREAD_DELAY = 2

IGNORE = ['jpeg', 'jpg', 'png', 'gif', 'mp3', 'mp4', 'wma', 'wmv', 'swf', 'swx', 'psd',\
          'pdf', 'ps', 'sql', 'pl', 'tar', 'gz', 'tgz', 'zip', 'rar', 'iso', 'bin', 'cue']

# status that deserve to be notified to user
NOTIFY_STATUS = [u'401', u'403', u'500', u'501']
REDIRECT = [u'301', u'302', u'303']
# The RegExps below are used to extract links from webpages
# the can be completed with new ones if needed but then also complete the
# code applying them in SpiderThread.__extract_links()
A_REGEXP = re.compile(r'<a.*?href=["|\']?(?P<url>.*?)["|\'|\s|>]', re.IGNORECASE)
IMG_REGEXP = re.compile(r'<img[\s]*src=["|\']?(?P<url>.*?)["|\'|\s|>]', re.IGNORECASE)
EMAIL_REGEXP = re.compile(r'\b[a-zA-Z0-9\._-]+@[a-zA-Z0-9-\.]+\.[a-zA-Z]{2,4}\b', re.IGNORECASE)
FRAME_REGEXP = re.compile(r'<frame.*?src=["|\']?(?P<url>.*?)["|\'|\s|>]', re.IGNORECASE)

ROBOTS_DIRS_REGEXP = re.compile(r'Disallow:\s(?P<dir>/.*/)', re.IGNORECASE)
ACCEPT_CONTENT_REGEXP = re.compile(u'text/html', re.IGNORECASE)

## ################################################################# ##
## CLI OUTPUT FUNCTIONS
## ################################################################# ##
## The possible result configurations issued by this module are:
## Generic error:               {ERROR}
## Error on a single target:    {HOST, PORT, IPADDRESS, ERROR}
## Target specification:        {HOST, PORT, IPADDRESS, TARGET}
## Found e-mail address:        {HOST, PORT, IPADDRESS, EMAIL}
## Found internal directory:    {HOST, PORT, IPADDRESS, INTERNAL}
## Found external link:         {HOST, PORT, IPADDRESS, EXTERNAL}
## ################################################################# ##

def cli_output_result(result):
    
    if result.has_key(u'ERROR'):
        print '% ERROR %\t' + result[u'ERROR'].encode(u'utf-8', u'replace')
        
    elif result.has_key(u'TARGET'):
        print ''
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        print result[u'TARGET']
        print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
        
    elif result.has_key(u'EMAIL'):
        print '% [ M ] %\t' + result[u'EMAIL'].encode(u'utf-8', u'replace')
    
    elif result.has_key(u'INTERNAL'):
        print '% [ I ] %\t' + result[u'INTERNAL'].encode(u'utf-8', u'replace')
    
    elif result.has_key(u'EXTERNAL'):
        print '% [ E ] %\t' + result[u'EXTERNAL'].encode(u'utf-8', u'replace')


## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##
## The functions below are used to INTERFACE this module with upper
## layers. As long as these functions exist (and have the same input
## and output parameters) all the rest of the module can be modified
## without interfering with upper levels using it.
## ################################################################# ##

def perform(host, port, root, cli, results, results_lock, switch, switch_lock):
    
# Input:  host - unicode - target host
#         port - unicode - target port
#         root - unicode - target root
#         cli - boolean - set verbosity on STDOUT to ON/OFF
#         results - [dict] - (shared) output results list
#         results_lock - threading.Lock - (shared) lock on the output list
#         switch - [boolean] - (shared) switch controlling scan life-cycle (ON/OFF)
#         switch_lock - threading.Lock - (shared) lock on switch
#        
# Return: (void)
#
# This function crawls a given website extracting all the encountered e-mail addresses
# external links and internal directories. The spider follows all the internal links and
# redirections and parses all the pages having a 'text/html' content-type. External links
# are extracted and returned as result but not followed.

    try:
        # Loading and testing config parameters
        threads = core_file.cfg_get_spider_threads(core_file.cfg_start_get())
        use_robots = core_file.cfg_get_use_robots(core_file.cfg_start_get())
        
        if not core_utilities.check_threads(threads):
            
            issue_result(results, results_lock, cli, {u'ERROR': u'Invalid configuration parameters. Please verify configuration file.'})
        
        else:
            
            ipaddress = core_utilities.get_ip_address(host)
            issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'TARGET': host + ' / ' + unicode(port)})
            
            # test if target is up and valid...
            http_test = core_http.test_http(host, port)
            if not http_test[0]:
                
                error_message = http_test[1]
                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'ERROR': error_message})
                
            else:
                
                running = []
                known = {}
                known[root] = False # put the root in the spider links to initiate
                known_lock = threading.Lock()
                
                # cheat.... #
                issue_result(results, results_lock, False, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INTERNAL': (dirname(root) + u'/').replace(u'//', u'/')})
                
                # grabbing robots.txt
                if use_robots:
                    
                    httpClient = core_http.HTTPClient(host, port)
                    request = core_http.HTTPRequest()
                    request.set_method(u'GET')
                    request.set_path(root + u'robots.txt')
                    response = httpClient.perform_request(request)
                    
                    if response != None:
                        
                        if response.get_code() == u'200':
                            robots_text = response.get_data()
                            robots_directories = ROBOTS_DIRS_REGEXP.findall(robots_text)
                            
                            for rdir in robots_directories:
                                # note that the last '/' is removed before putting it as a key
                                # in 'known' to comply with os.path.dirname used below that returns
                                # dirnames without last slash
                                if not known.has_key(rdir[:-1]):
                                    known[rdir[:-1]] = False 
                                else:
                                    continue
                                
                                issue_result(results, results_lock, cli, {u'HOST': host, u'PORT': unicode(port), u'IPADDRESS': ipaddress, u'INTERNAL': rdir})
                        else:
                            pass
                    else:
                        pass
                else: # ignore robots.txt
                    pass
                
                # start the first thread to grab the first page
                # and populate the 'known' dictionary with a few
                # results
                running.append(SpiderThread(host, port, ipaddress, known, known_lock, cli, results, results_lock, switch, switch_lock))
                running[0].start()
                sleep(THREAD_DELAY)

                # after a delay, spawn the other threads
                for i in range(1, threads):
                    spiderThread = SpiderThread(host, port, ipaddress, known, known_lock, cli, results, results_lock, switch, switch_lock)
                    spiderThread.start()
                    running.append(spiderThread)

                for thread in running:
                    thread.join()
                    
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
## INTERNAL CLASS: SpiderThread
## ################################################################# ##
## This class implements the thread used to spider the website.
## The threads share a dict containing all the gathered resources
## (internal/external links, emails,...) and a boolean indicating if
## the resource is (or not) a link that must be visited. Globally,
## all resources that are NOT internal links are directly set to True
## (True -> not to visit) and internal links are set to False
## (False -> to visit) until they are visited by some thread. The main
## interest of this approach is that it can be used to reference
## all known resources and thus avoid duplicates...
## All the collected elements are appended to the results (shared)
## list, independently of their type (note that results are 'self
## contained' - they contain all the required information to sort
## them and identify their type - thus there is no need to use
## separate lists to return them).
## ################################################################# ##

class SpiderThread(threading.Thread):
    
    def __init__(self, host, port, ipaddress, known, known_lock, cli, results, results_lock, switch, switch_lock):
        
        threading.Thread.__init__(self)
        
        self.__host = host
        self.__port = port
        self.__ipaddress = ipaddress
        self.__known = known
        self.__known_lock = known_lock
        self.__cli = cli
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        self.__httpClient = core_http.HTTPClient(self.__host, self.__port)
        self.__base = self.__host
        self.__links = 0
        
    ## ################################################################# ##
    
    def run(self):
    
        while self.__links < MAX_LINKS:
            
            with self.__switch_lock:
                on = self.__switch[0]
            
            if not on:
                break
            
            # fetch an unvisited link #
            more = False
            with self.__known_lock:
                for (link, visited) in self.__known.items():
                    if visited == False:
                        more = True
                        next = link
                        self.__known[link] = True
                        self.__links += 1
                        break
                    
            if not more:
                break
                
            else:
                # test if the extension indicates that the
                # document should be ignored
                if next.split('.')[-1] in IGNORE:
                    continue
                
                # if the extension is not in the list
                # of files to ignore, then send a HEAD
                # request to get the 'content-type' header.
                httpRequest = core_http.HTTPRequest()
                httpRequest.set_method(u'HEAD')
                httpRequest.set_path(next)
                httpHead = self.__httpClient.perform_request(httpRequest)
                
                if httpHead != None:
                    
                    status = httpHead.get_code()
                    content = httpHead.get_header(u'content-type')
                    
                    # if content type does not match accepted types (text/html)
                    # or if it is not provided do not request the body
                    if  content != None and ACCEPT_CONTENT_REGEXP.search(content):
                        
                        # if the response is a 200 OK, request the body
                        # using GET method and parse it
                        if status == u'200':
                            
                            httpRequest.set_method(u'GET')
                            httpResponse = self.__httpClient.perform_request(httpRequest)
                            
                            
                            if httpResponse != None:
                                
                                self.__extract_links(next, httpResponse)
                                self.__extract_emails(httpResponse)
                                continue
                            
                            else:
                                issue_result(self.__results, self.__results_lock, self.__cli, {u'ERROR': u'GET ' + httpRequest.get_path() + u' failed. Server may be overloaded.'})
                                continue
                        
                        # empyrical...
                        elif status in NOTIFY_STATUS:
                            
                            issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'ERROR': u'HEAD ' + next + ' => ' + status})
                            continue
                        
                        # if the response is a redirection, check if it
                        # is an internal redirection and follow it (or not)
                        # if it is not already known. If the redirection
                        # points to another website, don't follow it.
                        elif status in REDIRECT:
                            
                            redirection = httpHead.get_header(u'location')
                            
                            if redirection != None:
                                
                                redir_proto = urlparse.urlparse(redirection).scheme
                                redir_base = urlparse.urlparse(redirection).netloc
                                
                                if redir_base == u'': # relative internal link
                                
                                    redir_parse = urlparse.urlparse(urlparse.urljoin(u'http://' + self.__base + urlparse.urlparse(next).path, redirection))
                                    abs_redir = redir_parse.path
                                    #~ if redir_parse.query != u'':
                                        #~ abs_redir += u'?' + redir_parse.query
                                        
                                    with self.__known_lock:
                                        if not self.__known.has_key(abs_redir):
                                            
                                            if redir_proto == u'' or redir_proto == u'http':
                                                self.__known[abs_redir] = False # to visit
                                            else:
                                                self.__known[abs_redir] = True # not to visit
                                                
                                            if not self.__known.has_key(dirname(abs_redir)):
                                                self.__known[dirname(abs_redir)] = True # not to visit
                                            
                                                issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'INTERNAL': dirname(abs_redir) + u'/'})
                                                continue
                                            
                                            else:
                                                continue
                                        else:
                                            continue
                                
                                elif redir_base == self.__base: # absolute internal link
                                    
                                    temp_redir = urlparse.urlparse(redirection)
                                    temp_path = temp_redir.path
                                    #~ if temp_redir.query != u'':
                                        #~ temp_path += u'?' + temp_redir.query
                                    
                                    redir_parse = urlparse.urlparse(urlparse.urljoin(u'http://' + self.__base + urlparse.urlparse(next).path, temp_path))
                                    abs_redir = redir_parse.path
                                    #~ if redir_parse.query != u'':
                                        #~ abs_redir += u'?' + redir_parse.query
                                        
                                    with self.__known_lock:
                                        if not self.__known.has_key(abs_redir):
                                            
                                            if redir_proto == u'' or redir_proto == u'http':
                                                self.__known[abs_redir] = False # to visit
                                            else:
                                                self.__known[abs_redir] = True # not to visit
                                            
                                            if not self.__known.has_key(dirname(abs_redir)):
                                                self.__known[dirname(abs_redir)] = True # not to visit
                                                
                                                issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'INTERNAL': dirname(abs_redir) + u'/'})
                                                continue
                                            
                                            else:
                                                continue
                                        else:
                                            continue
                                        
                                else: # external
                                            
                                    abs_redir = redir_base
                                    with self.__known_lock:
                                        if not self.__known.has_key(abs_redir):
                                            self.__known[abs_redir] = True # not to visit
                                            
                                            issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'EXTERNAL': abs_redir})
                                            continue
                                            
                                        else:
                                            continue
                                    
                            else: # no 'location' header
                                continue
                        else: # other status code
                            continue
                    else: # content type != 'text/html
                        continue
                else: # request failed
                    issue_result(self.__results, self.__results_lock, self.__cli, {u'ERROR': u'HEAD ' + httpRequest.get_path() + u' failed. Server may be overloaded.'})
                    continue

    ## ################################################################# ##
    
    def __extract_emails(self, httpResponse):
        
        emails = EMAIL_REGEXP.findall(httpResponse.get_data())
        
        for email in emails:
            with self.__known_lock:
                
                if not self.__known.has_key(lower(email)):
                    self.__known[lower(email)] = True
                    
                    issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'EMAIL': lower(email)})
                    
                else:
                    continue
                
    ## ################################################################# ##
    
    def __extract_links(self, next, httpResponse):
        
        # if new RegExp are added to extract links, they
        # have to be applied here...
        links = A_REGEXP.findall(httpResponse.get_data())
        links.extend(IMG_REGEXP.findall(httpResponse.get_data()))
        links.extend(FRAME_REGEXP.findall(httpResponse.get_data()))
        
        for link in links:
            
            link_proto = urlparse.urlparse(link).scheme
            link_base = urlparse.urlparse(link).netloc
        
            if link_proto == u'mailto':
                
                continue
        
            if link_base == u'': # internal relative link
                
                temp = urlparse.urlparse(urlparse.urljoin(u'http://' + self.__base + urlparse.urlparse(next).path, link))
                abs_internal = temp.path
                
                #~ if temp.params != u'':
                    #~ abs_internal += u';' + temp.params
                #~ if temp.query != u'':
                    #~ abs_internal += u'?' + temp.query
            
                with self.__known_lock:
                    if not self.__known.has_key(abs_internal):
                        if link_proto == u'' or link_proto == u'http':
                            self.__known[abs_internal] = False # to visit
                        else:
                            self.__known[abs_internal] = True # not to visit
                        
                        if not self.__known.has_key(dirname(abs_internal)):
                            self.__known[dirname(abs_internal)] = True # not to visit
                        
                            issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'INTERNAL': dirname(abs_internal) + u'/'})
                            continue
                        
                        else:
                            continue
                    else:
                        continue
                    
            elif link_base == self.__base: # internal absolute link
                
                temp_link = urlparse.urlparse(link)
                link_path = temp_link.path
                #~ if temp_link.params != u'':
                    #~ link_path += u';' + temp_link.params
                #~ if temp_link.query != u'':
                    #~ link_path += u'?' + temp_link.query
                
                temp = urlparse.urlparse(urlparse.urljoin(u'http://' + self.__base + urlparse.urlparse(next).path, link_path))
                abs_internal = temp.path
                #~ if temp.params != u'':
                    #~ abs_internal += u';' + temp.params
                #~ if temp.query != u'':
                    #~ abs_internal += u'?' + temp.query
                
                with self.__known_lock:
                    if not self.__known.has_key(abs_internal):
                        if link_proto == u'' or link_proto == u'http':
                            self.__known[abs_internal] = False # to visit
                        else:
                            self.__known[abs_internal] = True # not to visit
                        
                        if not self.__known.has_key(dirname(abs_internal)):
                            self.__known[dirname(abs_internal)] = True # not to visit
                            
                            issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'INTERNAL': dirname(abs_internal) + u'/'})
                            continue
                        
                        else:
                            continue
                    else:
                        continue
                        
            else: # external
                abs_external = link_base
                with self.__known_lock:
                    if not self.__known.has_key(abs_external):
                        
                        self.__known[abs_external] = True
                        
                        issue_result(self.__results, self.__results_lock, self.__cli, {u'HOST': self.__host, u'PORT': unicode(self.__port), u'IPADDRESS': self.__ipaddress, u'EXTERNAL': abs_external})
                        continue
                    
                    else:
                        continue
