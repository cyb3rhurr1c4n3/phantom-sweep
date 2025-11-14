"""
JSON Output Plugin - Output results in JSON format
"""
import json
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class JsonPlugin(BasePlugin):
    """JSON output plugin"""
    
    def name(self) -> str:
        return "json"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Output
    
    def metadata(self):
        return {
            "name": "json",
            "display_name": "JSON Output",
            "description": "Output results in JSON format",
            "category": "output",
            "requires_root": False,
            "aliases": ["js"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Generate JSON output"""
        output_format = getattr(args, 'output', 'text')
        if 'json' not in output_format.split(','):
            return {}
        
        output_file = getattr(args, 'output_file', None)
        if not output_file:
            # If no output file, results are printed to console by CLI
            return {}
        
        try:
            print(f"[*] Đang tạo báo cáo JSON tại: {output_file}")
            
            # Get scan results
            tcp_results = context.get_data("scan_results") or {}
            udp_results = context.get_data("scan_results_udp") or {}
            
            # Combine results
            results = {
                "scan_type": context.scan_type,
                "targets": list(set(tcp_results.keys()) | set(udp_results.keys())),
                "tcp_results": tcp_results,
                "udp_results": udp_results
            }
            
            # Write JSON file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            print(f"    [SUCCESS] Đã lưu báo cáo JSON thành công vào: {output_file}")
        except Exception as e:
            print(f"    [ERROR] Lỗi khi lưu file báo cáo JSON {output_file}: {e}")
        
        return {}

