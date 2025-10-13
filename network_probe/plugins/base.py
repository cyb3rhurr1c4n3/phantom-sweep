# Định nghĩa các lớp cơ sở cho plugin
import abc
from typing import Dict, List

from network_probe.core.context import ScanContext
class BaseScanner(abc.ABC):
    @abc.abstractmethod
    def scan(self,target: List[str],context: ScanContext) -> Dict[str,any]:
        pass

class BaseReport(abc.ABC):
    @abc.abstractmethod
    def save(self,result: Dict[str,any],filename: str):
        pass
        