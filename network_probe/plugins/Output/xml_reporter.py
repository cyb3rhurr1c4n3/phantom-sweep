from typing import Dict
from network_probe.plugins.base_plugin import BaseReport


class XmlReporter(BaseReport):
    def save(self, results: Dict[str,any],filename: str):
        pass