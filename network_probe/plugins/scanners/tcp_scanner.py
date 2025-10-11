
from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.base import BaseScanner


class TCPScanner(BaseScanner):
    def scan(self, target: str,context: ScanContext) -> Dict[str,any]:
        pass