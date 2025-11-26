
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

class TCPConnectScanner(ScannerBase):
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan"
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        print("TCP Connect Scan Executed")