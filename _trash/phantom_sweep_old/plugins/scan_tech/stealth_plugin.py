"""
TCP SYN Stealth Scan Plugin - Fast SYN scan without completing TCP handshake
"""
import sys
from argparse import ArgumentParser
from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.syn_scanner import SynScanner


class StealthPlugin(BasePlugin):
    """TCP SYN stealth scan plugin"""
    
    def name(self) -> str:
        return "stealth"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "stealth",
            "display_name": "TCP SYN Stealth Scan",
            "description": "Fast SYN scan without completing TCP handshake",
            "category": "scan_tech",
            "requires_root": True,
            "aliases": ["syn", "syn_scan"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run TCP SYN stealth scan"""
        scan_tech = getattr(args, 'scan_tech', 'connect')
        if scan_tech != 'stealth':
            return {}
        
        try:
            scanner = SynScanner()
            scan_results = scanner.scan(context.targets, context, args)
            
            for target, data in scan_results.items():
                if isinstance(data, dict) and "error" in data:
                    print(f"[!] Lỗi khi quét {target}: {data['error']}")
            
            context.set_data("scan_results", scan_results)
            print(f"[*] TCP SYN Stealth Scan hoàn tất.")
            return scan_results
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    SYN scan yêu cầu quyền root.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi quét: {e}{Style.RESET_ALL}")
            return {}

