"""
ICMP Ping Plugin - Default host discovery using ICMP echo requests
"""
import sys
from argparse import ArgumentParser
from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.ping_scanner import PingScanner


class IcmpPlugin(BasePlugin):
    """ICMP ping plugin for host discovery"""
    
    def name(self) -> str:
        return "icmp"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "icmp",
            "display_name": "ICMP Echo Ping",
            "description": "Standard ICMP echo request/reply for host discovery",
            "category": "ping_tech",
            "requires_root": False,
            "aliases": ["ping", "echo"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        # CLI registration is handled by the main CLI parser
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run ICMP ping scan"""
        try:
            # Check if this plugin should run
            if context.ping_tech != 'icmp':
                return {}
            
            scanner = PingScanner()
            # Set ping method to ICMP for compatibility
            args.ping_method = 'icmp'
            
            # PingScanner.scan() only handles one target, so we need to loop
            scan_result = {}
            for target in context.targets:
                try:
                    result = scanner.scan(target, context)
                    scan_result[target] = result
                except Exception as e:
                    scan_result[target] = {"error": str(e)}
            
            for target, data in scan_result.items():
                if isinstance(data, dict) and "error" in data:
                    print(f"[!] Lỗi khi ping {target}: {data['error']}")
            
            context.set_data("scan_results", scan_result)
            context.set_data("host_discovery", scan_result)
            print(f"[*] ICMP Ping Scan hoàn tất.")
            return scan_result
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    ICMP ping có thể yêu cầu quyền root trên một số hệ thống.")
            return {}
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi ping: {e}{Style.RESET_ALL}")
            return {}

