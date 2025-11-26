
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

class TCPPingScanner(ScannerBase):
    @property
    def name(self) -> str:
        return "tcp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "TCP Ping Discovery"
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        print("TCP Ping discovery executed")