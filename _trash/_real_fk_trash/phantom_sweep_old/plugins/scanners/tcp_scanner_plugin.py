
from argparse import ArgumentParser
import sys

from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin

from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.tcp_scanner import TCPScanner

class TCPScannerPlugin(BasePlugin):
    def name(self)-> str:
        return "tcp_connect_scanner"

    def plugin_type(self) -> PluginType:
        return PluginType.Scan

    def register_cli(self, parse: ArgumentParser):
        scan_group=parse.add_mutually_exclusive_group()
        scan_group.add_argument(
            '-sT',
            '--tcp-connect',
            action="store_true",
            help="Thực hiện TCP connect scan"
        )

    def run(self, context: ScanContext, args):

        is_other_scan= args.ping_scan or args.tcp_syn or  args.udp_scan
        if is_other_scan and not args.tcp_connect:
            return 
        try:
            scanner=TCPScanner()
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    Kỹ thuật quét này yêu cầu quyền 'sudo'. Vui lòng chạy lại.")
            sys.exit(1)
        scan_results=scanner.scan(context.targets,context,args)
        for target,data in scan_results.items():
            if isinstance(data,dict) and "error" in data:
                print(f"[!] Lỗi khi quét {target}: {data['error']}")

        context.set_data("scan_results", scan_results)
        print(f"[*] TCP Scan hoàn tất.")
