from argparse import ArgumentParser
import sys

from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.udp_scanner import UDPScanner


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
        parse.add_argument(
            '--udp-interface',
            help="Interface dùng để sniff/gửi UDP raw packets"
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
        scan_result=scanner.scan(context.targets,context,args)
        for target,data in scan_result.items():
            if isinstance(data,dict) and "error" in data:
                print(f"[!] Lỗi khi quét {target}: {data['error']}")

        context.set_data("scan_results_udp", scan_result)
        print(f"[*] UDP Scan hoàn tất.")