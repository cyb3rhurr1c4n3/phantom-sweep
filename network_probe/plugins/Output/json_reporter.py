from typing import Dict
from network_probe.plugins.base_plugin import BaseReport
import json

class JsonReporter(BaseReport): # Chỗ này nên xài BaseReport hay BasePlugin v, thấy thầy Bin xài BasePlugin nên vẫn chưa hiểu lắm
    def save(self, results: Dict[str,any],filename: str):
        # Tạm thời như v đi
        if not filename.endswith(".json"): filename += ".json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)