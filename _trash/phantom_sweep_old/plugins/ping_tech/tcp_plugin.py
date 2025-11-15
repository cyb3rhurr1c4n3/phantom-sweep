"""
TCP Ping Plugin - Host discovery using TCP SYN/ACK packets
"""
import sys
from argparse import ArgumentParser
from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.ping_scanner import PingScanner


class TcpPingPlugin(BasePlugin):
    """TCP ping plugin for host discovery"""
    
    def name(self) -> str:
        return "tcp"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "tcp",
            "display_name": "TCP SYN/ACK Ping",
            "description": "Host discovery using TCP SYN or ACK packets",
            "category": "ping_tech",
            "requires_root": True,
            "aliases": ["tcp_ping", "syn_ping"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run TCP ping scan"""
        try:
            # Check if this plugin should run
            if context.ping_tech != 'tcp':
                return {}
            
            scanner = PingScanner()
            # Set ping method to TCP for compatibility
            args.ping_method = 'tcp'
            
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
            print(f"[*] TCP Ping Scan hoàn tất.")
            return scan_result
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    TCP ping yêu cầu quyền root.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi ping: {e}{Style.RESET_ALL}")
            return {}

