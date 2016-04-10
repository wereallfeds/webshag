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
## last mod: 2008-11-03

from xml.dom import minidom
from operator import itemgetter
from time import strftime
from webshag.core import core_file

## ################################################################# ##
## MODULE CONSTANTS
## ################################################################# ##

WEBSHAG = u'webshag'
WEBSHAG_VERSION = u'1.10'

## ################################################################# ##
## PUBLIC FUNCTIONS
## ################################################################# ##

def exp_report(filename, format='xml', infores=None, pscanres=None, uscanres=None, fuzzres=None, spidres=None):
    
    if format == 'xml':
        xml_document = __exp_xml(infores, pscanres, uscanres, fuzzres, spidres)
        try:
            core_file.exp_write_report(xml_document.toprettyxml(), filename)
            return True
        except IOError: # typically: permission denied....
            return False
    
    elif format == 'html':
        html_document = __exp_from_xml(u'html', infores, pscanres, uscanres, fuzzres, spidres)
        try:
            core_file.exp_write_report(html_document, filename)
            return True
        except IOError: # typically: permission denied....
            return False
        
    elif format == 'txt':
        txt_document = __exp_from_xml(u'txt', infores, pscanres, uscanres, fuzzres, spidres)
        try:
            core_file.exp_write_report(txt_document, filename)
            return True
        except IOError: # typically: permission denied....
            return False
    else:
        return False

## ################################################################# ##
## PRIVATE FUNCTIONS
## ################################################################# ##

def __sort_and_split(input, output, key):
    # input: list of dict
    # output: dict with lists of dict
    
    temp = []
    known = []
    
    for item in input:
        if item.has_key(key) and not item.has_key(u'ERROR'):
            temp.append(item)
        else:
            continue
    
    temp.sort(key=itemgetter(key))
    
    for result in temp:
        
        out_key = result[key]
        
        # avoid duplicates #
        if result in known:
            continue
        else:
            known.append(result)
            
            if output.has_key(out_key):
                output[out_key].append(result)
            else:
                output[out_key] = [result]


## ################################################################# ##

def __exp_xml(infores, pscanres, uscanres, fuzzres, spidres):
    
    xml_document = minidom.Document()
    
    report_element = xml_document.createElement(u'WSREPORT')
    report_element.setAttribute('date', strftime('%d-%m-%Y'))
    
    if pscanres != None:
        pscan_xml = __exp_portscan_xml(pscanres, xml_document)
        report_element.appendChild(pscan_xml)
        
    if infores != None:
        info_xml = __exp_info_xml(infores, xml_document)
        report_element.appendChild(info_xml)

    if spidres != None:
        spid_xml = __exp_spider_xml(spidres, xml_document)
        report_element.appendChild(spid_xml)
    
    if uscanres != None:
        uscan_xml = __exp_urlscan_xml(uscanres, xml_document)
        report_element.appendChild(uscan_xml)
        
    if fuzzres != None:
        fuzz_xml = __exp_fuzz_xml(fuzzres, xml_document)
        report_element.appendChild(fuzz_xml)
    
    xml_document.appendChild(report_element)
    
    return xml_document
    

## ################################################################# ##

def __exp_from_xml(format, infores, pscanres, uscanres, fuzzres, spidres):
    
    # supported formats: html, txt

    if format == u'html':
        exp_document = html_top()
    elif format == u'txt':
        exp_document = txt_top()
    
    xml_document = __exp_xml(infores, pscanres, uscanres, fuzzres, spidres)
    wsreport_element = xml_document.getElementsByTagName(u'WSREPORT')[0]
    
    
    # ###################################################### #
    # PSCAN RESULTS                                          #
    # ###################################################### #
    for pscan_element in wsreport_element.getElementsByTagName(u'PSCAN'):
        
        if format == u'html':
            exp_document += html_module(u'Port Scanner')
        elif format == u'txt':
            exp_document += txt_module(u'Port Scanner')
            
        for ipaddress_element in pscan_element.getElementsByTagName(u'IPADDRESS'):
            ipaddress = ipaddress_element.getAttribute('id')
            
            if format == u'html':
                exp_document += html_target(ipaddress, None, None)
            elif format == u'txt':
                exp_document += txt_target(ipaddress, None, None)
                
            
            for result_element in ipaddress_element.getElementsByTagName(u'RESULT'):
                
                portid = protocol = srvname = srvproduct = srvos = u''
                for portid_element in result_element.getElementsByTagName(u'PORTID'):
                    portid = portid_element.firstChild.data.strip()
                for protocol_element in result_element.getElementsByTagName(u'PROTOCOL'):
                    protocol = protocol_element.firstChild.data.strip()
                for srvname_element in result_element.getElementsByTagName(u'SRVNAME'):
                    srvname = srvname_element.firstChild.data.strip()
                for srvproduct_element in result_element.getElementsByTagName(u'SRVPRODUCT'):
                    srvproduct = srvproduct_element.firstChild.data.strip()
                for srvos_element in result_element.getElementsByTagName(u'SRVOS'):
                    srvos = srvos_element.firstChild.data.strip()
                
                if format == u'html':
                    exp_document += html_pscan(portid, protocol, srvname, srvproduct, srvos)
                elif format == u'txt':
                    exp_document += txt_pscan(portid, protocol, srvname, srvproduct, srvos)
        
        if format == u'html':
            exp_document += html_post_module()


    # ###################################################### #
    # INFO RESULTS                                           #
    # ###################################################### #
    for info_element in wsreport_element.getElementsByTagName(u'INFO'):
        
        if format == u'html':
            exp_document += html_module(u'Info')
        elif format == u'txt':
            exp_document += txt_module(u'Info')
        
        for ipaddress_element in info_element.getElementsByTagName(u'IPADDRESS'):
            ipaddress = ipaddress_element.getAttribute('id')
                
            if format == u'html':
                exp_document += html_target(ipaddress, None, None)
            elif format == u'txt':
                exp_document += txt_target(ipaddress, None, None)
            
            for vhost_element in ipaddress_element.getElementsByTagName(u'VHOST'):
                vhost = vhost_element.firstChild.data.strip()
                
                if format == u'html':
                    exp_document += html_info(vhost)
                elif format == u'txt':
                    exp_document += txt_info(vhost)
            
        if format == u'html':
            exp_document += html_post_module()
            
    # ###################################################### #
    # SPIDER RESULTS                                         #
    # ###################################################### #
    for spider_element in wsreport_element.getElementsByTagName(u'SPIDER'):
        
        if format == u'html':
            exp_document += html_module(u'Spider')
        elif format == u'txt':
            exp_document += txt_module(u'Spider')
        
        for ipaddress_element in spider_element.getElementsByTagName(u'IPADDRESS'):
            ipaddress = ipaddress_element.getAttribute('id')
            
            for port_element in ipaddress_element.getElementsByTagName(u'PORT'):
                port = port_element.getAttribute(u'id')
                
                for host_element in ipaddress_element.getElementsByTagName(u'HOST'):
                    host = host_element.getAttribute(u'id')
                    
                    if format == u'html':
                        exp_document += html_target(ipaddress, port, host)
                    elif format == u'txt':
                        exp_document += txt_target(ipaddress, port, host)
                    
                    if format == u'html':
                        exp_document += html_spider_split('Internal Directories')
                    elif format == u'txt':
                        exp_document += txt_spider_split('Internal Directories')
                    
                    for internal_element in host_element.getElementsByTagName(u'INTERNAL'):
                        internal = internal_element.firstChild.data.strip()
                        
                        if format == u'html':
                            exp_document += html_spider(internal)
                        elif format == u'txt':
                            exp_document += txt_spider(internal)
                        
                    if format == u'html':
                        exp_document += html_spider_split('Email Addresses')
                    elif format == u'txt':
                        exp_document += txt_spider_split('Email Addresses')
                        
                    for email_element in host_element.getElementsByTagName(u'EMAIL'):
                        email = email_element.firstChild.data.strip()
                        
                        if format == u'html':
                            exp_document += html_spider(email)
                        elif format == u'txt':
                            exp_document += txt_spider(email)
                    
                    if format == u'html':
                        exp_document += html_spider_split('External Links')
                    elif format == u'txt':
                        exp_document += txt_spider_split('External Links')
                        
                    for external_element in host_element.getElementsByTagName(u'EXTERNAL'):
                        external = external_element.firstChild.data.strip()
                        
                        if format == u'html':
                            exp_document += html_spider(external)
                        elif format == u'txt':
                            exp_document += txt_spider(external)
                    
        if format == u'html':
            exp_document += html_post_module()
            
    # ###################################################### #
    # USCAN RESULTS                                          #
    # ###################################################### #
    for uscan_element in wsreport_element.getElementsByTagName(u'USCAN'):
        
        if format == u'html':
            exp_document += html_module(u'URL Scanner')
        elif format == u'txt':
            exp_document += txt_module(u'URL Scanner')
    
        for ipaddress_element in uscan_element.getElementsByTagName(u'IPADDRESS'):
            ipaddress = ipaddress_element.getAttribute('id')
            
            for port_element in ipaddress_element.getElementsByTagName(u'PORT'):
                port = port_element.getAttribute(u'id')
                
                for host_element in port_element.getElementsByTagName(u'HOST'):
                    host = host_element.getAttribute(u'id')
                    
                    if format == u'html':
                        exp_document += html_target(ipaddress, port, host)
                    elif format == u'txt':
                        exp_document += txt_target(ipaddress, port, host)
                    
                    
                    for result_element in host_element.getElementsByTagName(u'RESULT'):
                        
                        banner = server = info = path = code = description = u''
                        
                        for banner_element in result_element.getElementsByTagName(u'BANNER'):
                            banner = banner_element.firstChild.data.strip()
                        for server_element in result_element.getElementsByTagName(u'SERVER'):
                            server = server_element.firstChild.data.strip()
                        
                        
                        for path_element in result_element.getElementsByTagName(u'PATH'):
                            path = path_element.firstChild.data.strip()
                        for code_element in result_element.getElementsByTagName(u'CODE'):
                            code = code_element.firstChild.data.strip()
                        for description_element in result_element.getElementsByTagName(u'DESCRIPTION'):
                            description = description_element.firstChild.data.strip()
                        
                        if banner != u'' and server != u'':
                            if format == u'html':
                                exp_document += html_uscan_banner(banner, server)
                            elif format == u'txt':
                                exp_document += txt_uscan_banner(banner, server)
                        
                        else:
                            if format == u'html':
                                exp_document += html_uscan_result(path, code, description)
                            elif format == u'txt':
                                exp_document += txt_uscan_result(path, code, description)
                                
        if format == u'html':
            exp_document += html_post_module()
            
    # ###################################################### #
    # FUZZ RESULTS                                          #
    # ###################################################### #
    for fuzz_element in wsreport_element.getElementsByTagName(u'FUZZ'):
        
        if format == u'html':
            exp_document += html_module(u'File Fuzzer')
        elif format == u'txt':
            exp_document += txt_module(u'File Fuzzer')
    
        for ipaddress_element in fuzz_element.getElementsByTagName(u'IPADDRESS'):
            ipaddress = ipaddress_element.getAttribute('id')
            
            for port_element in ipaddress_element.getElementsByTagName(u'PORT'):
                port = port_element.getAttribute(u'id')
                
                for host_element in port_element.getElementsByTagName(u'HOST'):
                    host = host_element.getAttribute(u'id')
                    
                    if format == u'html':
                        exp_document += html_target(ipaddress, port, host)
                    elif format == u'txt':
                        exp_document += txt_target(ipaddress, port, host)
                    
                    for result_element in host_element.getElementsByTagName(u'RESULT'):
                        for path_element in result_element.getElementsByTagName(u'PATH'):
                            path = path_element.firstChild.data.strip()
                        for code_element in result_element.getElementsByTagName(u'CODE'):
                            code = code_element.firstChild.data.strip()
                        
                        if format == u'html':   
                            exp_document += html_fuzz_result(path, code)
                        elif format == u'txt':
                            exp_document += txt_fuzz_result(path, code)
                            
        if format == u'html':
            exp_document += html_post_module()
    
    if format == u'html':
        exp_document += html_bottom()
    elif format == u'txt':
        exp_document += txt_bottom()
        
    return exp_document

## ################################################################# ##

def __exp_spider_xml(results, xml_document=None):
    
    if xml_document == None:
        xml_document = minidom.Document()
        retdoc = True
    else:
        retdoc = False
    
    scan_element = xml_document.createElement(u'SPIDER')
    
    sort_ip = {}
    __sort_and_split(results, sort_ip, u'IPADDRESS')
    
    for ip in sort_ip.keys():
        
        ip_element = xml_document.createElement(u'IPADDRESS')
        ip_element.setAttribute('id', ip)
        
        sort_port = {}
        __sort_and_split(sort_ip[ip], sort_port, u'PORT')
        
        for port in sort_port.keys():
            
            port_element = xml_document.createElement(u'PORT')
            port_element.setAttribute('id', port)
            
            sort_host = {}
            __sort_and_split(sort_port[port], sort_host, u'HOST')
            
            
            for host in sort_host.keys():
                
                host_element = xml_document.createElement(u'HOST')
                host_element.setAttribute('id', host)
                
                # first pass: internal directories
                for result in sort_host[host]:
                    
                    if result.has_key(u'INTERNAL'):
                        internal_element = xml_document.createElement(u'INTERNAL')
                        internal_text = xml_document.createTextNode(result[u'INTERNAL'])
                        internal_element.appendChild(internal_text)
                        
                        host_element.appendChild(internal_element)
                        
                    else:
                        
                        pass
                    
                # second pass: email addresses
                for result in sort_host[host]:
                    
                    if result.has_key(u'EMAIL'):
                        
                        email_element = xml_document.createElement(u'EMAIL')
                        email_text = xml_document.createTextNode(result[u'EMAIL'])
                        email_element.appendChild(email_text)
                        
                        host_element.appendChild(email_element)
                        
                    else:
                        
                        pass
                
                # last pass: external links
                for result in sort_host[host]:
                    
                    if result.has_key(u'EXTERNAL'):
                        external_element = xml_document.createElement(u'EXTERNAL')
                        external_text = xml_document.createTextNode(result[u'EXTERNAL'])
                        external_element.appendChild(external_text)
                        
                        host_element.appendChild(external_element)
                        
                    else:
                        
                        pass
                
                port_element.appendChild(host_element)
            
            ip_element.appendChild(port_element)
            
        scan_element.appendChild(ip_element)
        
    xml_document.appendChild(scan_element)
    
    if retdoc:
        return xml_document
    else:
        return scan_element


## ################################################################# ##

def __exp_info_xml(results, xml_document=None):
    
    if xml_document == None:
        xml_document = minidom.Document()
        retdoc = True
    else:
        retdoc = False
        
    scan_element = xml_document.createElement(u'INFO')
    
    sort_ip = {}
    __sort_and_split(results, sort_ip, u'IPADDRESS')
    
    for ip in sort_ip.keys():
        
        ip_element = xml_document.createElement(u'IPADDRESS')
        ip_element.setAttribute('id', ip)
        
        for result in sort_ip[ip]:
            
            if result.has_key(u'TARGET'):
                continue
            else:
                vhost_element = xml_document.createElement(u'VHOST')
                vhost_text = xml_document.createTextNode(result[u'VHOST'])
                vhost_element.appendChild(vhost_text)
                ip_element.appendChild(vhost_element)
            
        scan_element.appendChild(ip_element)
        
    xml_document.appendChild(scan_element)

    if retdoc:
        return xml_document
    else:
        return scan_element



## ################################################################# ##

def __exp_portscan_xml(results, xml_document=None):
    
    if xml_document == None:
        xml_document = minidom.Document()
        retdoc = True
    else:
        retdoc = False
        
    scan_element = xml_document.createElement(u'PSCAN')
    
    sort_ip = {}
    __sort_and_split(results, sort_ip, u'IPADDRESS')
    
    for ip in sort_ip.keys():
        
        ip_element = xml_document.createElement(u'IPADDRESS')
        ip_element.setAttribute('id', ip)
        
        for result in sort_ip[ip]:
            
            result_element = xml_document.createElement(u'RESULT')
            
            if result.has_key(u'TARGET'):
                
                continue
            
            if result.has_key(u'PORTID'):
                
                portid_element = xml_document.createElement(u'PORTID')
                portid_text = xml_document.createTextNode(result[u'PORTID'])
                portid_element.appendChild(portid_text)
                result_element.appendChild(portid_element)
                
            if result.has_key(u'PROTOCOL'):
                
                protocol_element = xml_document.createElement(u'PROTOCOL')
                protocol_text = xml_document.createTextNode(result[u'PROTOCOL'])
                protocol_element.appendChild(protocol_text)
                result_element.appendChild(protocol_element)
                
            if result.has_key(u'SRV_NAME'):
                
                srvname_element = xml_document.createElement(u'SRVNAME')
                srvname_text = xml_document.createTextNode(result[u'SRV_NAME'])
                srvname_element.appendChild(srvname_text)
                result_element.appendChild(srvname_element)
                
            if result.has_key(u'SRV_PRODUCT'):
                
                srvproduct_element = xml_document.createElement(u'SRVPRODUCT')
                srvproduct_text = xml_document.createTextNode(result[u'SRV_PRODUCT'])
                srvproduct_element.appendChild(srvproduct_text)
                result_element.appendChild(srvproduct_element)
            
            if result.has_key(u'SRV_OS'):
                
                srvos_element = xml_document.createElement(u'SRVOS')
                srvos_text = xml_document.createTextNode(result[u'SRV_OS'])
                srvos_element.appendChild(srvos_text)
                result_element.appendChild(srvos_element)
                
                
            ip_element.appendChild(result_element)
                
        scan_element.appendChild(ip_element)
        
    xml_document.appendChild(scan_element)

    if retdoc:
        return xml_document
    else:
        return scan_element


## ################################################################# ##

def __exp_fuzz_xml(results, xml_document=None):
    
    if xml_document == None:
        xml_document = minidom.Document()
        retdoc = True
    else:
        retdoc = False
        
    scan_element = xml_document.createElement(u'FUZZ')
    
    sort_ip = {}
    __sort_and_split(results, sort_ip, u'IPADDRESS')
    
    known_ips = []
    for ip in sort_ip.keys():
        
        if ip in known_ips:
            continue
        else:
            known_ips.append(ip)
        
            ip_element = xml_document.createElement(u'IPADDRESS')
            ip_element.setAttribute('id', ip)
            
            sort_port = {}
            __sort_and_split(sort_ip[ip], sort_port, u'PORT')
            
            known_ports = []
            for port in sort_port.keys():
                
                if port in known_ports:
                    continue
                else:
                    known_ports.append(port)
                
                    port_element = xml_document.createElement(u'PORT')
                    port_element.setAttribute('id', port)
                    
                    sort_host = {}
                    __sort_and_split(sort_port[port], sort_host, u'HOST')
                    
                    known_hosts = []
                    for host in sort_host.keys():
                        
                        if host in known_hosts:
                            continue
                        else:
                            known_hosts.append(host)
                        
                            host_element = xml_document.createElement(u'HOST')
                            host_element.setAttribute('id', host)
                            
                            for result in sort_host[host]:
                                
                                if result.has_key(u'TARGET') or result.has_key(u'INFO'):
                                    
                                    continue
                                
                                else:
                                
                                    result_element = xml_document.createElement(u'RESULT')
                                    
                                    path_element = xml_document.createElement(u'PATH')
                                    path_text = xml_document.createTextNode(result[u'PATH'])
                                    path_element.appendChild(path_text)
                                    result_element.appendChild(path_element)
                                    
                                    code_element = xml_document.createElement(u'CODE')
                                    code_text = xml_document.createTextNode(result[u'CODE'])
                                    code_element.appendChild(code_text)
                                    result_element.appendChild(code_element)
                                    
                                    host_element.appendChild(result_element)
                                    
                            port_element.appendChild(host_element)
                    
                    ip_element.appendChild(port_element)
                
            scan_element.appendChild(ip_element)
        
    xml_document.appendChild(scan_element)
    
    if retdoc:
        return xml_document
    else:
        return scan_element

## ################################################################# ##

def __exp_urlscan_xml(results, xml_document=None):
    
    if xml_document == None:
        xml_document = minidom.Document()
        retdoc = True
    else:
        retdoc = False
        
    scan_element = xml_document.createElement(u'USCAN')
    
    sort_ip = {}
    __sort_and_split(results, sort_ip, u'IPADDRESS')
    
    known_ips = []
    for ip in sort_ip.keys():
        
        if ip in known_ips:
            continue
        else:
            known_ips.append(ip)
        
            ip_element = xml_document.createElement(u'IPADDRESS')
            ip_element.setAttribute('id', ip)
            
            sort_port = {}
            __sort_and_split(sort_ip[ip], sort_port, u'PORT')
            
            known_ports = []
            for port in sort_port.keys():
                
                if port in known_ports:
                    continue
                else:
                    known_ports.append(port)
                
                    port_element = xml_document.createElement(u'PORT')
                    port_element.setAttribute('id', port)
                    
                    sort_host = {}
                    __sort_and_split(sort_port[port], sort_host, u'HOST')
                    
                    known_hosts = []
                    for host in sort_host.keys():
                        
                        if host in known_hosts:
                            continue
                        else:
                            known_hosts.append(host)
                        
                            host_element = xml_document.createElement(u'HOST')
                            host_element.setAttribute('id', host)
                            
                            # first pass - locate 'server'
                            for result in sort_host[host]:
                                
                                if result.has_key(u'BANNER'):
                                    
                                    result_element = xml_document.createElement(u'RESULT')
                                    
                                    banner_element = xml_document.createElement(u'BANNER')
                                    banner_text = xml_document.createTextNode(result[u'BANNER'])
                                    banner_element.appendChild(banner_text)
                                    result_element.appendChild(banner_element)
                                    
                                    server_element = xml_document.createElement(u'SERVER')
                                    server_text = xml_document.createTextNode(result[u'SERVER'])
                                    server_element.appendChild(server_text)
                                    result_element.appendChild(server_element)
                                    
                                    host_element.appendChild(result_element)
                                    
                                else:
                                    
                                    pass
                            
                            # second pass - other results
                            for result in sort_host[host]:
                                
                                if result.has_key(u'BANNER') or result.has_key(u'INFO') or result.has_key(u'TARGET'):
                                    
                                    pass
                                
                                else:
                                    
                                    result_element = xml_document.createElement(u'RESULT')
                                
                                    path_element = xml_document.createElement(u'PATH')
                                    path_text = xml_document.createTextNode(result[u'PATH'])
                                    path_element.appendChild(path_text)
                                    result_element.appendChild(path_element)
                                    
                                    code_element = xml_document.createElement(u'CODE')
                                    code_text = xml_document.createTextNode(result[u'CODE'])
                                    code_element.appendChild(code_text)
                                    result_element.appendChild(code_element)
                                    
                                    description_element = xml_document.createElement(u'DESCRIPTION')
                                    description_text = xml_document.createTextNode(result[u'DESCRIPTION'])
                                    description_element.appendChild(description_text)
                                    result_element.appendChild(description_element)
                                    
                                    host_element.appendChild(result_element)
                                    
                            port_element.appendChild(host_element)
                    
                    ip_element.appendChild(port_element)
                
            scan_element.appendChild(ip_element)
        
    xml_document.appendChild(scan_element)
    
    if retdoc:
        return xml_document
    else:
        return scan_element


## ################################################################# ##
## FORMATING RELATED FUNCTIONS
## ################################################################# ##

## HTML ############################################################ ##

def html_top():
    return """
<html>
    <head><title>""" + WEBSHAG + u'/' + WEBSHAG_VERSION + """</title></head>
    <body bgcolor='#FFFFFF'>
        <font face='courier new'>
            <table width='100%' border='0'>
                <tr>
                    <td align='left'><big><big><big><b>Audit Report</b></big></big></big></td>
                    <td align='right'><a href='http://www.scrt.ch'>""" + WEBSHAG + u'/' + WEBSHAG_VERSION + """</a></td>
                </tr>
                <tr>
                    <td colspan='2' align='left'>""" + strftime('%d-%m-%Y') + """</td>
                </tr>
                <tr>
                    <td colspan='2'>&nbsp;</td>
                </tr>
            </table>
    """

def html_module(name):
    return """
            <table width='100%' border='0'>
                <tr>
                    <td colspan='2'>&nbsp;</td>
                </tr>
                <tr bgcolor='#BBBBBB'>
                    <td colspan='2' align='left'><big><big><big><b>""" + name + """</b></big></big></big></td>
                </tr>
                <tr>
                    <td colspan='2'>&nbsp;</td>
                </tr>
    """

def html_target(ipaddress, port, host):
    html = """
                <tr>
                    <td colspan='2'>&nbsp;</td>
                </tr>
                <tr bgcolor='#DEDEDE'>
                    <td colspan='2' align='left'><big><b>""" + ipaddress
    
    if port != None:
        html += ' / ' + port
    
    if host != None:
        html += ' / ' + host
    
    html += """</b></big></td>
                </tr>
                <tr>
                    <td colspan='2'>&nbsp;</td>
                </tr>
    """
    
    return html
    

def html_pscan(port, protocol, name, product, opsys):
    result = """
                <tr>
                    <td align='left' colspan='2'><b>""" + port + """ (""" + protocol + """)</b></td>
                </tr>
    """
    if name != u'':
        result += """
                <tr>
                    <td colspan='1' width='20%' align='left'>Service: </td>
                    <td colspan='1' width='80%' >""" + name + """</td>
                </tr>
                """
    if product != u'':
        result += """
                <tr>
                    <td colspan='1' width='20%' align='left'>Product: </td>
                    <td colspan='1' width='80%' >""" + product + """</td>
                </tr>
                """
    if opsys != u'':
        result += """
                <tr>
                    <td colspan='1' width='20%' align='left'>OS: </td>
                    <td colspan='1' width='80%' >""" + opsys + """</td>
                </tr>
                """
                
    return result

def html_info(vhost):
    return """
    <tr>
        <td align='left' colspan='2'>""" + vhost + """</td>
    </tr>
    """

def html_spider_split(type):
    return """
    <tr>
        <td align='left' colspan='2'><b>""" + type + """</b></td>
    </tr>
    """

def html_spider(result):
    return """
    <tr>
        <td align='left' colspan='2'>""" + result + """</td>
    </tr>
    """
    
def html_uscan_banner(banner, server):
    return """
    <tr>
        <td align='left' colspan='2'><b>Server Banner: """ + banner + """ (""" + server + """)</b></td>
    </tr>
    <tr>
        <td colspan='2'>&nbsp;</td>
    </tr>
    """

def html_uscan_result(path, code, description):
    path = path.replace('<', '&lt;')
    path = path.replace('>', '&gt;')
    description = description.replace('<', '&lt;')
    description = description.replace('>', '&gt;')
    
    return """
    <tr>
        <td align='left' width='10%' colspan='1'>[<b>""" + code + """</b>]</td>
        <td align='left' width='90%' colspan='1'><b>""" + path + """</b></td>
    </tr>
    <tr>
        
        <td align='left' colspan='2'>""" + description + """</td>
    </tr>
    <tr>
        <td colspan='2'>&nbsp;</b></td>
    </tr>
    """

def html_fuzz_result(path, code):
    path = path.replace('<', '&lt;')
    path = path.replace('>', '&gt;')
    return """
    <tr>
        <td align='left' width='10%' colspan='1'>""" + code + """</td>
        <td align='left' width='90%' colspan='1'>""" + path + """</td>
    </tr>
    """

def html_post_module():
    return """</table>"""

def html_bottom():
    return """
            </font>
        </body>
    </html>
    """

## TEXT ############################################################ ##


def txt_top():
    return WEBSHAG + u' / ' + WEBSHAG_VERSION + '\n' + strftime('%d-%m-%Y') + '\n\n'

def txt_bottom():
    return ''

def txt_module(name):
    return  """
##########################################
""" + name + """
##########################################

"""

def txt_target(ipaddress, port, host):
    
    txt = '\n#### ' + ipaddress
    
    if port != None:
        txt += ' / ' + port
        
    if host != None:
        txt += ' / ' + host
    
    txt += ' ####\n\n'
    
    return txt

def txt_pscan(port, protocol, name, product, opsys):
    result = port + ' (' + protocol + ')'
    
    if name != u'':
        result += ' / ' + name
        
    if product != u'':
        result += ' / ' + product
        
    if opsys != u'':
        result += ' / ' + opsys
    
    result += '\n'
    
    return result

def txt_info(vhost):
    return vhost + '\n'

def txt_spider_split(type):
    return u'\n# ' + type +' #\n\n'

def txt_spider(result):
    return result + '\n'

def txt_uscan_banner(banner, server):
    return 'Banner: ' + banner + ' (' + server + ')\n'

def txt_uscan_result(path, code, description):
    return '[' + code + '] ' + path + '\n' + description + '\n'

def txt_fuzz_result(path, code):
    return '[' + code + '] ' + path + '\n'
