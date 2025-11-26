
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

class TCPSynScanner(ScannerBase):
    @property
    def name(self) -> str:
        return "stealth"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Syn Scan (stealth scan)"
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        print("TCP Syn Scan Executed")