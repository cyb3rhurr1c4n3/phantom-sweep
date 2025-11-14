"""
UDP Scan Plugin - Port scanning using UDP packets
"""
import sys
from argparse import ArgumentParser
from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.scanners.udp_scanner import UDPScanner


class UdpPlugin(BasePlugin):
    """UDP scan plugin"""
    
    def name(self) -> str:
        return "udp"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "udp",
            "display_name": "UDP Scan",
            "description": "UDP port scanning",
            "category": "scan_tech",
            "requires_root": True,
            "aliases": ["udp_scan"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run UDP scan"""
        scan_tech = getattr(args, 'scan_tech', 'connect')
        if scan_tech != 'udp':
            return {}
        
        try:
            scanner = UDPScanner()
            scan_results = scanner.scan(context.targets, context, args)
            
            for target, data in scan_results.items():
                if isinstance(data, dict) and "error" in data:
                    print(f"[!] Lỗi khi quét {target}: {data['error']}")
            
            context.set_data("scan_results_udp", scan_results)
            print(f"[*] UDP Scan hoàn tất.")
            return scan_results
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    UDP scan yêu cầu quyền root.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi quét: {e}{Style.RESET_ALL}")
            return {}

