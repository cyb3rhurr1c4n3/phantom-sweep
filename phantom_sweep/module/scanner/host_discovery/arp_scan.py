
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

class ARPScanner(ScannerBase):
    @property
    def name(self) -> str:
        return "arp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "ARP Discovery"

    def scan(self, context: ScanContext, result: ScanResult) -> None:
        print("ARP discovery executed")