
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
import sys
import threading
from typing import Dict, List

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin

from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.scanners.syn_scanner import SynScanner

# Sorry ô Bin nhiều nha, tui lười code lại từ đầu quá :((((((

Fast_Scan_Port=[7, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3268, 3269, 3389, 5900, 8080, 8443, 1025, 1026, 1027, 1028, 1029, 1030,
    113, 199, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    902, 1080, 1099, 123, 137, 138, 161, 162, 177, 1720, 2000, 2049, 2121,
    2717, 3000, 3128, 3478, 3702, 49152, 49153, 49154, 49155, 49156, 49157,
    500, 5060, 5222, 5223, 5228, 5357, 5432, 5631, 5666, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49158,
    49159, 49160, 49161, 49162, 49163]



class SYNScannerPlugin(BasePlugin):
    def name(self)-> str:
        return "syn_scanner"

    def plugin_type(self) -> PluginType:
        return PluginType.Scan

    def register_cli(self, parse: ArgumentParser):
        scan_group=parse.add_mutually_exclusive_group()
        scan_group.add_argument(
            '-sS',
            '--tcp-syn',
            action="store_true",
            help="Thực hiện SYN scan"
        )

    def run(self, context: ScanContext, args):
        other_scan_active = False
        # if hasattr(args, 'tcp_scan') and args.tcp_scan:
        #     other_scan_active = True

        # is_default_scan = (not other_scan_active) and (not args.tcp_syn)

        # if not args.tcp_connect and not is_default_scan:
        #     return
        
        if not args.tcp_syn:
            return
        try:
            scanner=SynScanner()
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    Kỹ thuật quét này yêu cầu quyền 'sudo'. Vui lòng chạy lại.")
            sys.exit(1)
        scan_results={}
        lock=threading.Lock()
        def scan_target(target):
            try:
                result=scanner.scan(target,context)
                with lock:
                    if "error" in result:
                        print(f"[!] Lỗi khi quét {target}: {result['error']}")
                    scan_results[target]=result
            except Exception as e:
                print(f"[!] Lỗi khi quét {target}: {e}")
        with ThreadPoolExecutor(max_workers=context.threads) as executor:
            executor.map(scan_target, context.targets)
                
        context.set_data("scan_results", scan_results)
        print(f"[*] SYN Scan hoàn tất.")
