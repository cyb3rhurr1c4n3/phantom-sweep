
from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.scanners.ping_scanner import PingScaner
from network_probe.plugins.scanners.syn_scanner import SynScanner
from network_probe.plugins.scanners.tcp_scanner import TCPScanner


class ScanEngine:
    def __init__(self, context: ScanContext):
        self.context=context

        self.scanner_map={
            "tcp":TCPScanner,
            "syn":SynScanner,
            "ping":PingScaner
        }
    def run_scan(self)-> Dict[any,str]:
        scan_type=self.context.scan_type

        scanner_class=self.scanner_map.get(scan_type)

        if not scanner_class:
            print(f"[Error] Kiểu quét {scan_type} không được hỗ trợ")
            return {}
        
        scanner=scanner_class()
        result={}

        for target in self.context.targets:
            try:
                result_data=scanner.scan(target,self.context)
                result[target]=result_data
            except Exception as e:
                print(f"[Error] Lỗi {e}")
                result[target]={"error",str(e)}
        return result
