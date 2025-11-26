from argparse import ArgumentParser
import sys

from colorama import Fore, Style
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
from phantom_sweep.plugins.scanners.ping_scanner import PingScanner

Fast_Scan_Port=[7, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3268, 3269, 3389, 5900, 8080, 8443, 1025, 1026, 1027, 1028, 1029, 1030,
    113, 199, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    902, 1080, 1099, 123, 137, 138, 161, 162, 177, 1720, 2000, 2049, 2121,
    2717, 3000, 3128, 3478, 3702, 49152, 49153, 49154, 49155, 49156, 49157,
    500, 5060, 5222, 5223, 5228, 5357, 5432, 5631, 5666, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49158,
    49159, 49160, 49161, 49162, 49163]
    
class PingScannerPlugin(BasePlugin):
    def name(self)-> str:
        return "ping_scan"

    def plugin_type(self) -> PluginType:
        return PluginType.Scan

    def register_cli(self, parse: ArgumentParser):
        scan_group=parse.add_mutually_exclusive_group()
        scan_group.add_argument(
            '-sn',
            '--ping-scan',
            action="store_true",
            dest="ping_scan",
            help="Ping scanner"
        )
        parse.add_argument(
            '--ping-method',
            choices=['icmp','tcp','arp'],
            default='icmp',
            help="Chọn kỹ thuật Host Discovery (icmp, tcp, arp)"
        )
        parse.add_argument(
            '--ping-tcp-port',
            type=int,
            default=80,
            help="Cổng đích cho TCP SYN/ACK Ping (mặc định: 80)"
        )
        parse.add_argument(
            '--ping-tcp-flag',
            choices=['syn','ack'],
            default='syn',
            help="Kiểu gói TCP Ping (SYN hoặc ACK)"
        )
        parse.add_argument(
            '--ping-interface',
            dest='ping_interface',
            help="Interface sử dụng cho raw socket ping (đặc biệt với ARP)"
        )
        parse.add_argument(
            '--ping-rate',
            dest='ping_rate',
            type=int,
            help="Giới hạn tốc độ gửi gói Ping (gói/giây)"
        )


    def run(self, context: ScanContext, args):
        if not args.ping_scan:
            return
        try:
            scanner=PingScanner()
        except PermissionError as e:
            print(f"Không có quyền để quét {e}")
            print("    Ping scan (-sn) yêu cầu quyền 'sudo'/'Administrator'.")
            sys.exit(1)
        try:
            scan_result=scanner.scan(context.targets,context,args)
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi nghiêm trọng khi ping: {e}{Style.RESET_ALL}")
            return

        for target,data in scan_result.items():
            if isinstance(data,dict) and "error" in data:
                print(f"[!] Lỗi khi quét {target}: {data['error']}")

        context.set_data("scan_results", scan_result)
        context.set_data("host_discovery", scan_result)
        print(f"[*] Ping Scan hoàn tất.")