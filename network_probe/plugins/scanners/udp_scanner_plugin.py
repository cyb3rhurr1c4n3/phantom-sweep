from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
import sys
import threading

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.scanners.udp_scanner import UDPScanner


class UDPScannerPLugin(BasePlugin):
    def name(self)-> str:
        return "udp_scan"

    def plugin_type(self) -> PluginType:
        return PluginType.Scan

    def register_cli(self, parse: ArgumentParser):
        group_scan=parse.add_mutually_exclusive_group()
        group_scan.add_argument(
            '-sU',
            '--udp-scan',
            action="store_true",
            help="Udp scanner"
        )

    def run(self, context: ScanContext, args):
        if not args.udp_scan:
            return
        try:
            scanner=UDPScanner()
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    UDP scan (-sU) yêu cầu quyền 'sudo'/'Administrator'.")
            sys.exit(1)
        scan_result={}
        lock=threading.Lock()
        def scan_target(target):
            try:
                result=scanner.scan(target,context)
                with lock:
                    if "error" in result:
                        print(f"[!] Lỗi khi quét {target}: {result['error']}")
                    scan_result[target]=result
            except Exception as e:
                print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi quét UDP {target}: {e}{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=context.threads) as executor:
            executor.map(scan_target, context.targets)
            
        context.set_data("scan_results_udp", scan_result)
        print(f"[*] UDP Scan hoàn tất.")