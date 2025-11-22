from typing import Dict
from network_probe.plugins.base_plugin import BaseReport
from dicttoxml import dicttoxml

class XmlReporter(BaseReport):
    def save(self, results: Dict[str,any],filename: str):
        # Tạm thời như v đi
        if not filename.endswith(".xml"): filename += ".xml"
        pass # ...idk