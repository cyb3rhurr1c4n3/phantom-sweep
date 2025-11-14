
from argparse import ArgumentParser
import sys

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin

from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.scanners.syn_scanner import SynScanner


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
        if not args.tcp_syn:
            return
        try:
            scanner=SynScanner()
        except PermissionError as e:
            print(f"{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
            print("    Kỹ thuật quét này yêu cầu quyền 'sudo'. Vui lòng chạy lại.")
            sys.exit(1)
        scan_results=scanner.scan(context.targets,context,args)
        for target,data in scan_results.items():
            if isinstance(data,dict) and "error" in data:
                print(f"[!] Lỗi khi quét {target}: {data['error']}")

        context.set_data("scan_results", scan_results)
        print(f"[*] SYN Scan hoàn tất.")
