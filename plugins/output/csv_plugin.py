"""
CSV Output Plugin - Output results in CSV format
"""
import csv
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class CsvPlugin(BasePlugin):
    """CSV output plugin"""
    
    def name(self) -> str:
        return "csv"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Output
    
    def metadata(self):
        return {
            "name": "csv",
            "display_name": "CSV Output",
            "description": "Output results in CSV format",
            "category": "output",
            "requires_root": False,
            "aliases": []
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Generate CSV output"""
        output_format = getattr(args, 'output', 'text')
        if 'csv' not in output_format.split(','):
            return {}
        
        output_file = getattr(args, 'output_file', None)
        if not output_file:
            return {}
        
        try:
            print(f"[*] Đang tạo báo cáo CSV tại: {output_file}")
            
            # Get scan results
            tcp_results = context.get_data("scan_results") or {}
            udp_results = context.get_data("scan_results_udp") or {}
            all_targets = set(tcp_results.keys()) | set(udp_results.keys())
            
            # Write CSV file
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Target", "Protocol", "Port", "State", "Service"])
                
                for target in sorted(all_targets):
                    # TCP ports
                    if target in tcp_results:
                        for port, details in tcp_results[target].get("ports", {}).items():
                            writer.writerow([
                                target,
                                "tcp",
                                port,
                                details.get("state", "unknown"),
                                details.get("service", "")
                            ])
                    
                    # UDP ports
                    if target in udp_results:
                        for port, details in udp_results[target].get("ports", {}).items():
                            writer.writerow([
                                target,
                                "udp",
                                port,
                                details.get("state", "unknown"),
                                details.get("service", "")
                            ])
            
            print(f"    [SUCCESS] Đã lưu báo cáo CSV thành công vào: {output_file}")
        except Exception as e:
            print(f"    [ERROR] Lỗi khi lưu file báo cáo CSV {output_file}: {e}")
        
        return {}

