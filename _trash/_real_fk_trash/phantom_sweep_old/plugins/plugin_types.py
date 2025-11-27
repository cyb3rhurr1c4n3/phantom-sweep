from enum import Enum, auto

class PluginType(Enum):
    Scan=auto()
    Analyze=auto()
    Output=auto()