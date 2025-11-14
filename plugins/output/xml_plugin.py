"""
XML Output Plugin - Output results in XML format
"""
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class XmlPlugin(BasePlugin):
    """XML output plugin"""
    
    def name(self) -> str:
        return "xml"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Output
    
    def metadata(self):
        return {
            "name": "xml",
            "display_name": "XML Output",
            "description": "Output results in XML format",
            "category": "output",
            "requires_root": False,
            "aliases": []
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Generate XML output"""
        output_format = getattr(args, 'output', 'text')
        if 'xml' not in output_format.split(','):
            return {}
        
        output_file = getattr(args, 'output_file', None)
        if not output_file:
            return {}
        
        try:
            print(f"[*] Đang tạo báo cáo XML tại: {output_file}")
            
            # Create root element
            root = ET.Element("nmaprun")
            root.set("scanner", "PhantomSweep")
            root.set("args", str(args))
            
            # Get scan results
            tcp_results = context.get_data("scan_results") or {}
            udp_results = context.get_data("scan_results_udp") or {}
            all_targets = set(tcp_results.keys()) | set(udp_results.keys())
            
            # Add hosts
            for target in sorted(all_targets):
                host_elem = ET.SubElement(root, "host")
                address_elem = ET.SubElement(host_elem, "address")
                address_elem.set("addr", target)
                address_elem.set("addrtype", "ipv4")
                
                # Add ports
                ports_elem = ET.SubElement(host_elem, "ports")
                
                # TCP ports
                if target in tcp_results:
                    for port, details in tcp_results[target].get("ports", {}).items():
                        port_elem = ET.SubElement(ports_elem, "port")
                        port_elem.set("protocol", "tcp")
                        port_elem.set("portid", str(port))
                        state_elem = ET.SubElement(port_elem, "state")
                        state_elem.set("state", details.get("state", "unknown"))
                        if "service" in details:
                            service_elem = ET.SubElement(port_elem, "service")
                            service_elem.set("name", details.get("service", "unknown"))
                
                # UDP ports
                if target in udp_results:
                    for port, details in udp_results[target].get("ports", {}).items():
                        port_elem = ET.SubElement(ports_elem, "port")
                        port_elem.set("protocol", "udp")
                        port_elem.set("portid", str(port))
                        state_elem = ET.SubElement(port_elem, "state")
                        state_elem.set("state", details.get("state", "unknown"))
            
            # Write XML file
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ")
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            print(f"    [SUCCESS] Đã lưu báo cáo XML thành công vào: {output_file}")
        except Exception as e:
            print(f"    [ERROR] Lỗi khi lưu file báo cáo XML {output_file}: {e}")
        
        return {}

