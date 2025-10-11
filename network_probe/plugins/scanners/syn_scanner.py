

from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.base import BaseScanner


class SynScanner(BaseScanner):
    def scan(self, taret: str, context: ScanContext ) -> Dict[str,any]:
        pass