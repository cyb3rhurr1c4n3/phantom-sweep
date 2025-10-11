from typing import Dict
from network_probe.plugins.base import BaseReport


class HtmlReporter(BaseReport):
    def save(self, results: Dict[str,any],filename: str):
        pass