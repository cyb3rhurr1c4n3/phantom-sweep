from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BaseScanner


class SynScanner(BaseScanner):
    def scan(self, target: str, context: ScanContext ) -> Dict[str,any]:
        pass
