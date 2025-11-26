"""
TCP Connect Scan Plugin - Default port scanning using TCP connect()
"""
import sys
from argparse import ArgumentParser
from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.tcp_scanner import TCPScanner


class ConnectPlugin(BasePlugin):
    """TCP Connect scan plugin - default port scanning"""
    
    def name(self) -> str:
        return "connect"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "connect",
            "display_name": "TCP Connect Scan",
            "description": "Standard TCP connect() scan, no root required",
            "category": "scan_tech",
            "requires_root": False,
            "aliases": ["tcp_connect", "tcp"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run TCP connect scan"""
        scan_tech = getattr(args, 'scan_tech', 'connect')
        if scan_tech != 'connect':
            return {}
        
        try:
            scanner = TCPScanner()
            scan_results = scanner.scan(context.targets, context, args)
            
            for target, data in scan_results.items():
                if isinstance(data, dict) and "error" in data:
                    print(f"[!] Lỗi khi quét {target}: {data['error']}")
            
            context.set_data("scan_results", scan_results)
            print(f"[*] TCP Connect Scan hoàn tất.")
            return scan_results
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            return {}
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi quét: {e}{Style.RESET_ALL}")
            return {}

