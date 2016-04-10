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

from __future__ import with_statement

import sys
import os.path
from time import sleep
from threading import Thread, Lock
from optparse import OptionParser

from webshag.core import core_utilities, core_file
from webshag.modules import module_info, module_uscan, module_pscan, module_fuzz, module_spider
from webshag.export import export
from webshag.update import update

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

WEBSHAG = u'webshag'
WEBSHAG_VERSION = u'1.10'

MODULE_PSCAN = 'pscan'
MODULE_INFO = 'info'
MODULE_SPIDER = 'spider'
MODULE_USCAN = 'uscan'
MODULE_FUZZ = 'fuzz'

MODULES = [MODULE_PSCAN, MODULE_INFO, MODULE_SPIDER, MODULE_USCAN, MODULE_FUZZ]
FUZZ_MODE_GEN = u'gen'
FUZZ_MODE_LIST = u'list'
FUZZ_MODES = [FUZZ_MODE_GEN, FUZZ_MODE_LIST] 
OUTPUT_XML = u'xml'
OUTPUT_HTML = u'html'
OUTPUT_TXT = u'txt'
DEFAULT_MODULE = MODULE_USCAN
DEFAULT_SKIP = u''
DEFAULT_SERVER = u''
DEFAULT_PORT = u'80'
DEFAULT_ROOT = u'/'
DEFAULT_FUZZ_MODE = FUZZ_MODE_LIST
DEFAULT_FUZZ_CONFIG = u'11'
DEFAULT_FUZZ_GENERATOR = u''
DEFAULT_SPIDER_INIT = u'/'
DEFAULT_OUTPUT = OUTPUT_HTML
DEFAULT_OUTPUT_FILE = u'webshag_report.html'
OUTPUT = [OUTPUT_XML, OUTPUT_HTML, OUTPUT_TXT]


## ################################################################# ##
## PRIVATE FUNCTIONS
## ################################################################# ##

def __update_databases():
    
    success_nikto = update.update_nikto_database()
    __cli_print_update(u'Nikto', success_nikto)
    success_custom = update.update_custom_database()  
    __cli_print_update(u'SCRT', success_custom)

## ################################################################# ##

def __run(module_settings, export_settings):
    
    results = []
    results_lock = Lock()
    switch = [True]
    switch_lock = Lock()
    
    __cli_print_start(module_settings, export_settings)
    
    
    runner = ModuleRunner(module_settings, results, results_lock, switch, switch_lock)
    runner.start()
    
    while runner.isAlive():
        try:
            # active wait #
            sleep(1)
            
        except KeyboardInterrupt:
            with switch_lock:
                switch[0] = False
    
    if switch[0] == True and export_settings[u'EXPORT'] == True:
        
        module = module_settings[u'MODULE']
        if module == MODULE_PSCAN:
            
            success = export.exp_report(export_settings[u'FILE'], export_settings[u'FORMAT'], pscanres=results)
            __cli_print_export(success, export_settings[u'FILE'])
            
        elif module == MODULE_INFO:
            
            success = export.exp_report(export_settings[u'FILE'], export_settings[u'FORMAT'], infores=results)
            __cli_print_export(success, export_settings[u'FILE'])
            
        elif module == MODULE_SPIDER:
            
            success = export.exp_report(export_settings[u'FILE'], export_settings[u'FORMAT'], spidres=results)
            __cli_print_export(success, export_settings[u'FILE'])
            
        elif module == MODULE_USCAN:
            
            success = export.exp_report(export_settings[u'FILE'], export_settings[u'FORMAT'], uscanres=results)
            __cli_print_export(success, export_settings[u'FILE'])
        
        elif module == MODULE_FUZZ:
            
            success = export.exp_report(export_settings[u'FILE'], export_settings[u'FORMAT'], fuzzres=results)
            __cli_print_export(success, export_settings[u'FILE'])
    else:
        pass
    
    
    __cli_print_end()
## ################################################################# ##

def __cli_print_start(module_settings, export_settings):
    
    module = module_settings[u'MODULE']

    print '~~~~~~~~~~~~~~~~~~~~~~~~~~ ## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
    print '% ' + WEBSHAG + ' ' + WEBSHAG_VERSION
    print '% Module: ' + module
    
    if module == MODULE_USCAN:
        print '% Host(s): ' + module_settings[u'HOSTS']
        print '% Port(s): ' + module_settings[u'PORTS']
        print '% Root(s): ' + module_settings[u'ROOTS']
    elif module == MODULE_FUZZ:
        print '% Host(s): ' + module_settings[u'HOSTS']
        print '% Port(s): ' + module_settings[u'PORTS']
        print '% Root(s): ' + module_settings[u'ROOTS']
        print '% Mode Settings: ' + module_settings[u'MODE'][0] + ' / ' + module_settings[u'MODE'][1]
    elif module == MODULE_PSCAN or module == MODULE_INFO:
        print '% Host: ' + module_settings[u'HOST']
    else:
        print '% Host: ' + module_settings[u'HOST']
        print '% Port: ' + module_settings[u'PORT']
        print '% Root: ' + module_settings[u'ROOT']
    
    if export_settings[u'EXPORT']:
        print '%'
        print '% Export format: ' + export_settings[u'FORMAT']
        print '% Export file: ' + export_settings[u'FILE']
        
    print '~~~~~~~~~~~~~~~~~~~~~~~~~~ ## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'

## ################################################################# ##

def __cli_print_end():
    print '~~~~~~~~~~~~~~~~~~~~~~~~~~ ## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'

## ################################################################# ##

def __cli_print_export(success, filename):
    if success:
        print 'Report successfully exported to ' + filename
    else:
        print 'Export of report failed (you may not have the appropriate rights).'

## ################################################################# ##

def __cli_print_update(dbname, success):
    if success:
        print 'Update of ' + dbname + ' database successful!'
    else:
        print 'Update of ' + dbname + ' database failed!'


## ################################################################# ##
## CLASS: ModuleRunner
## ################################################################# ##
## This class is in charge of running the attack modules as threads
## ################################################################# ##
    
class ModuleRunner(Thread):
    
    def __init__(self, module_settings, results, results_lock, switch, switch_lock):
        
        Thread.__init__(self)
        
        self.__module_settings = module_settings
        self.__results = results
        self.__results_lock = results_lock
        self.__switch = switch
        self.__switch_lock = switch_lock
        
    def run(self):
        
        cli = True
        
        module = self.__module_settings[u'MODULE']
        
        if module == MODULE_PSCAN:
            host = self.__module_settings[u'HOST']
            module_pscan.perform(host, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        
        elif module == MODULE_INFO:
            host = self.__module_settings[u'HOST']
            module_info.perform(host, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        
        elif module == MODULE_SPIDER:
            host = self.__module_settings[u'HOST']
            port = int(self.__module_settings[u'PORT'])
            root = self.__module_settings[u'ROOT']
            module_spider.perform(host, port, root, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        
        elif module == MODULE_USCAN:
            hosts = [h.strip() for h in self.__module_settings[u'HOSTS'].split(u',')]
            ports = [int(p.strip()) for p in self.__module_settings[u'PORTS'].split(u',')]
            roots = [r.strip() for r in self.__module_settings[u'ROOTS'].split(u',')]
            skip = self.__module_settings[u'SKIP']
            server = self.__module_settings[u'SERVER']
            module_uscan.perform(hosts, ports, roots, server, skip, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
        
        elif module == MODULE_FUZZ:
            hosts = [h.strip() for h in self.__module_settings[u'HOSTS'].split(u',')]
            ports = [int(p.strip()) for p in self.__module_settings[u'PORTS'].split(u',')]
            roots = [r.strip() for r in self.__module_settings[u'ROOTS'].split(u',')]
            mode = self.__module_settings[u'MODE']
            
            if mode[0] == FUZZ_MODE_GEN:
                generator = mode[1]
                module_fuzz.perform(hosts, ports, roots, 1, generator, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)
            else:
                extension = mode[1]
                module_fuzz.perform(hosts, ports, roots, 0, extension, cli, self.__results, self.__results_lock, self.__switch, self.__switch_lock)

## ################################################################# ##
## MAIN
## ################################################################# ##

def main():
    
    usage_string = "usage: %prog [-U | [options] target(s)]"
    version_string = '%prog ' + WEBSHAG_VERSION
    parser = OptionParser(usage=usage_string, version=version_string)
    
    parser.add_option('-U', dest='update', action='store_true', default=False, help='Update the URL scanner databases and exit')
    
    parser.add_option('-m', dest='module', default=DEFAULT_MODULE, help='Use MODULE [' + MODULE_PSCAN + '|' + MODULE_INFO + '|' + MODULE_SPIDER + '|' + MODULE_USCAN + '|' + MODULE_FUZZ + ']. (default: ' + DEFAULT_MODULE + ')')
    parser.add_option('-p', dest='port', default=DEFAULT_PORT, help='Set target port to PORT. For modules ' + MODULE_USCAN + ' and ' + MODULE_FUZZ + ' PORT can be a list of ports [port1,port2,...]. (default: ' + DEFAULT_PORT + ')')
    parser.add_option('-r', dest='root', default=DEFAULT_ROOT, help='Set root directory to ROOT. For modules ' + MODULE_USCAN + ' and ' + MODULE_FUZZ + ' ROOT can be a list of directories [/root1/,/root2/,...]. (default: ' + DEFAULT_ROOT + ')')
    
    parser.add_option('-k', dest='skip', default=DEFAULT_SKIP, help='*' + MODULE_USCAN + ' only* Set a false positive detection string')
    parser.add_option('-s', dest='server', default=DEFAULT_SERVER, help='*' + MODULE_USCAN + ' only* Bypass server detection and force server as SERVER')
    
    parser.add_option('-i', dest='spider_init', default=DEFAULT_SPIDER_INIT, help='*' + MODULE_SPIDER + ') only* Set spider initial crawling page (default: ' + DEFAULT_SPIDER_INIT + ')')
    
    parser.add_option('-n', dest='fuzz_mode', default=DEFAULT_FUZZ_MODE, help='*' + MODULE_FUZZ + ' only* Choose the fuzzing mode [' + FUZZ_MODE_LIST + '|' + FUZZ_MODE_GEN + ']. (default: ' + DEFAULT_FUZZ_MODE + ')')
    parser.add_option('-e', dest='fuzz_cfg', default=DEFAULT_FUZZ_CONFIG, help='*' + MODULE_FUZZ + ' / ' + FUZZ_MODE_LIST + ' only* Set the fuzzing parameters for list mode. 11 = fuzz directories and files; 01 = fuzz files only; 10 = fuzz directories only; 00 = fuzz nothing. (default: ' + DEFAULT_FUZZ_CONFIG + ')')
    parser.add_option('-g', dest='fuzz_gen', default=DEFAULT_FUZZ_GENERATOR, help='*' + MODULE_FUZZ + ' / ' + FUZZ_MODE_GEN + ' only* Set the filename generator expression. Refer to documentation for syntax reference. (default: ' + DEFAULT_FUZZ_GENERATOR + ')')

    parser.add_option('-x', dest='export', action='store_true', default=False, help='Export a report summarizing results.')
    parser.add_option('-o', dest='output', default=DEFAULT_OUTPUT, help='Set the format of the exported report. [' + OUTPUT_XML + '|' + OUTPUT_HTML + '|' + OUTPUT_TXT + ']. (default: ' + DEFAULT_OUTPUT + ')')
    parser.add_option('-f', dest='output_file', default=DEFAULT_OUTPUT_FILE, help='Write report to FILE. (default: ' + DEFAULT_OUTPUT_FILE + ')')
    
    (options, arguments) = parser.parse_args()
    
    
    if options.update :
        
        __update_databases()
        
    elif options.module != None and options.module in MODULES and len(arguments) > 0:
        
        target = ','.join(a.strip() for a in arguments)
        
        if core_utilities.check_host_list(target):
            check_target = True
            nb_target = len(target.split(u','))
            
        else:
            check_target = False
        
        if check_target:
            
            # ###################################################### #
            #                APPLICATION SETTINGS                    #
            # ###################################################### #
            
            # ###################################################### #
            # MODULE = PSCAN                                         #
            # ###################################################### #
            if options.module == MODULE_PSCAN:
                
                if nb_target == 1:
                    
                    module_settings = {}
                    module_settings[u'MODULE'] = MODULE_PSCAN
                    module_settings[u'HOST'] = target
                    
                    setup = True
                    
                else: 
                    setup = False
                    error_message = u'Too many targets specified for module ' + options.module
            
            # ###################################################### #
            # MODULE = INFO                                          #
            # ###################################################### #
            elif options.module == MODULE_INFO:
                
                if nb_target == 1:
                    
                    module_settings = {}
                    module_settings[u'MODULE'] = MODULE_INFO
                    module_settings[u'HOST'] = target
                    
                    setup = True
                    
                else:
                    setup = False
                    error_message = u'Too many targets specified for module ' + options.module
            
            # ###################################################### #
            # MODULE = SPIDER                                        #
            # ###################################################### #
            elif options.module == MODULE_SPIDER:
                
                if nb_target == 1:
                    
                    if core_utilities.check_spider_root(options.spider_init) and core_utilities.check_port_string(options.port):
                    
                        module_settings = {}
                        module_settings[u'MODULE'] = MODULE_SPIDER
                        module_settings[u'HOST'] = target
                        module_settings[u'PORT'] = options.port
                        module_settings[u'ROOT'] = options.spider_init
                        
                        setup = True
                        
                    else:
                        setup = False
                        error_message = u'Invalid parameter values for module ' + options.module
                else:
                    setup = False
                    error_message = u'Too many targets specified for module ' + options.module
                
            
            # ###################################################### #
            # MODULE = USCAN                                         #
            # ###################################################### #
            elif options.module == MODULE_USCAN:
                
                if core_utilities.check_port_list(options.port) and core_utilities.check_root_list(options.root) and core_utilities.check_ascii_string(options.server) and core_utilities.check_generic_string(options.skip):
                    
                    module_settings = {}
                    module_settings[u'MODULE'] = MODULE_USCAN
                    module_settings[u'HOSTS'] = target
                    module_settings[u'PORTS'] = options.port
                    module_settings[u'ROOTS'] = options.root
                    module_settings[u'SKIP'] = options.skip
                    module_settings[u'SERVER'] = options.server
                    
                    setup = True
                
                else:
                    setup = False
                    error_message = u'Invalid parameter values for module ' + options.module
                
                
            # ###################################################### #
            # MODULE = FUZZ                                          #
            # ###################################################### #
            elif options.module == MODULE_FUZZ:
                
                if core_utilities.check_port_list(options.port) and core_utilities.check_root_list(options.root) and options.fuzz_mode in FUZZ_MODES:
                    
                    if options.fuzz_mode == FUZZ_MODE_LIST and core_utilities.check_fuzz_config(options.fuzz_cfg):
                        
                        module_settings = {}
                        module_settings[u'MODULE'] = MODULE_FUZZ
                        module_settings[u'HOSTS'] = target
                        module_settings[u'PORTS'] = options.port
                        module_settings[u'ROOTS'] = options.root
                        module_settings[u'MODE'] = (options.fuzz_mode, options.fuzz_cfg)
                        
                        setup = True
                        
                    elif options.fuzz_mode == FUZZ_MODE_GEN and core_utilities.check_generic_string(options.fuzz_gen):
                        
                        module_settings = {}
                        module_settings[u'MODULE'] = MODULE_FUZZ
                        module_settings[u'HOSTS'] = target
                        module_settings[u'PORTS'] = options.port
                        module_settings[u'ROOTS'] = options.root
                        module_settings[u'MODE'] = (options.fuzz_mode, options.fuzz_gen)
                        
                        setup = True
                    
                    else:
                        setup = False
                        error_message = u'Invalid parameter values for module ' + options.module
                
                else:
                    setup = False
                    error_message = u'Invalid parameter values for module ' + options.module
             
            
            # ###################################################### #
            #                   EXPORT SETTINGS                      #
            # ###################################################### #
            
            if options.export:
                
                if options.output in OUTPUT and core_utilities.check_save_file_path(os.path.realpath(options.output_file)):
                    
                    export_settings = {}
                    export_settings[u'EXPORT'] = True
                    export_settings[u'FORMAT'] = options.output
                    export_settings[u'FILE'] = os.path.realpath(options.output_file)
                    
                    exp_setup = True
                
                else:
                    
                    exp_setup = False
                    exp_error_message = u'Invalid export parameter values'
                
            else:
                
                export_settings = {}
                export_settings[u'EXPORT'] = False
                export_settings[u'FORMAT'] = u''
                export_settings[u'FILE'] = u''
                
                exp_setup = True
                
            # ###################################################### #
            #                         RUNNING                        #
            # ###################################################### #
            
            if setup:
                if exp_setup:
                    __run(module_settings, export_settings)
                else:
                    parser.error(exp_error_message)
            else:
                parser.error(error_message)
        else: # target does not pass check
            parser.error("Invalid target(s) specified")
            
    else: # bad module or target
        parser.error("bad module or target missing")



if __name__ == "__main__":
    main()
