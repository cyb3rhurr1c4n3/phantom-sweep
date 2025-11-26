"""
XML Reporter - Nmap-compatible XML output format
"""
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Optional
from datetime import datetime
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ReporterBase


class XMLReporter(ReporterBase):
    """
    XML Reporter - Outputs scan results in Nmap-compatible XML format.
    """
    
    @property
    def name(self) -> str:
        return "xml"
    
    @property
    def type(self) -> str:
        return "reporter"
    
    @property
    def description(self) -> str:
        return "Nmap-compatible XML format"
    
    def export(self, context: ScanContext, result: ScanResult, filename: Optional[str] = None) -> None:
        """
        Export scan results in Nmap-compatible XML format.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult containing scan results
            filename: Optional filename to save output. If None, print to stdout.
        """
        # Update statistics
        result.update_statistics()
        
        # Create root element
        nmaprun = ET.Element('nmaprun')
        nmaprun.set('scanner', 'phantomsweep')
        nmaprun.set('args', self._build_args_string(context))
        nmaprun.set('start', str(int(datetime.fromisoformat(result.scan_start_time).timestamp())) if result.scan_start_time else '0')
        nmaprun.set('startstr', result.scan_start_time if result.scan_start_time else '')
        nmaprun.set('version', '1.0')
        nmaprun.set('xmloutputversion', '1.05')
        
        # Add scan info section
        scaninfo = ET.SubElement(nmaprun, 'scaninfo')
        scaninfo.set('type', context.pipeline.scan_tech)
        scaninfo.set('protocol', 'tcp')
        scaninfo.set('numservices', str(len([p for h in result.hosts.values() for p in h.tcp_ports])))
        if context.ports.port:
            scaninfo.set('services', context.ports.port)
        
        # Add verbose element
        verbose = ET.SubElement(nmaprun, 'verbose')
        verbose.set('level', '1' if context.verbose else '0')
        
        # Add debugging element
        debugging = ET.SubElement(nmaprun, 'debugging')
        debugging.set('level', '1' if context.debug else '0')
        
        # Add host elements
        for host_addr in sorted(result.hosts.keys()):
            host_info = result.hosts[host_addr]
            self._add_host_element(nmaprun, host_addr, host_info)
        
        # Add run stats
        runstats = ET.SubElement(nmaprun, 'runstats')
        
        finished = ET.SubElement(runstats, 'finished')
        finished.set('time', str(int(datetime.fromisoformat(result.scan_end_time).timestamp())) if result.scan_end_time else '0')
        finished.set('timestr', result.scan_end_time if result.scan_end_time else '')
        finished.set('summary', f"PhantomSweep done at {result.scan_end_time}")
        finished.set('elapsed', str(result.scan_duration) if result.scan_duration else '0')
        finished.set('exit', 'success')
        
        hosts = ET.SubElement(runstats, 'hosts')
        hosts.set('up', str(result.up_hosts))
        hosts.set('down', str(result.total_hosts - result.up_hosts))
        hosts.set('total', str(result.total_hosts))
        
        # Pretty print XML
        xml_str = self._prettify_xml(nmaprun)
        
        # Write output
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(xml_str)
            except Exception as e:
                print(f"[!] Error writing to {filename}: {e}")
        else:
            # Print to stdout
            print(xml_str)
    
    def _add_host_element(self, parent, host_addr, host_info):
        """Add host element to XML tree"""
        host = ET.SubElement(parent, 'host')
        host.set('starttime', '')
        host.set('endtime', '')
        
        # Status
        status = ET.SubElement(host, 'status')
        status.set('state', host_info.state)
        status.set('reason', 'user-set' if host_info.state == 'up' else 'no-response')
        status.set('reason_ttl', '0')
        
        # Address
        address = ET.SubElement(host, 'address')
        address.set('addr', host_addr)
        address.set('addrtype', 'ipv4')
        
        # Hostnames
        hostnames_elem = ET.SubElement(host, 'hostnames')
        hostname = ET.SubElement(hostnames_elem, 'hostname')
        hostname.set('name', host_addr)
        hostname.set('type', 'PTR')
        
        # Ports
        ports = ET.SubElement(host, 'ports')
        
        # TCP ports
        if host_info.tcp_ports:
            for port_num in sorted(host_info.tcp_ports.keys()):
                port_info = host_info.tcp_ports[port_num]
                self._add_port_element(ports, 'tcp', port_num, port_info)
        
        # UDP ports
        if host_info.udp_ports:
            for port_num in sorted(host_info.udp_ports.keys()):
                port_info = host_info.udp_ports[port_num]
                self._add_port_element(ports, 'udp', port_num, port_info)
        
        # OS detection
        if host_info.os:
            osmatch = ET.SubElement(host, 'osmatch')
            osmatch.set('name', host_info.os)
            osmatch.set('accuracy', str(host_info.os_accuracy or 0))
            osmatch.set('line', '')
    
    def _add_port_element(self, parent, protocol, port_num, port_info):
        """Add port element to ports section"""
        port = ET.SubElement(parent, 'port')
        port.set('protocol', protocol)
        port.set('portid', str(port_num))
        
        # State
        state = ET.SubElement(port, 'state')
        state.set('state', port_info.state)
        state.set('reason', 'syn-ack' if port_info.state == 'open' else 'reset')
        state.set('reason_ttl', '0')
        
        # Service
        service = ET.SubElement(port, 'service')
        service.set('name', port_info.service or 'unknown')
        if port_info.version:
            service.set('product', port_info.version)
        service.set('method', 'table')
        service.set('conf', '3')
    
    def _build_args_string(self, context) -> str:
        """Build command line arguments string for XML output"""
        args = ['phantom']
        
        # Add targets
        args.extend(context.targets.host[:5])  # Limit for brevity
        if len(context.targets.host) > 5:
            args.append('...')
        
        # Add options
        if context.pipeline.ping_tech != 'icmp':
            args.append(f'--ping-tech {context.pipeline.ping_tech}')
        if context.pipeline.scan_tech != 'connect':
            args.append(f'--scan-tech {context.pipeline.scan_tech}')
        if context.ports.port != 'top_1000':
            args.append(f'--port {context.ports.port}')
        
        return ' '.join(args)
    
    def _prettify_xml(self, elem) -> str:
        """Return a pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding='UTF-8').decode('UTF-8')
