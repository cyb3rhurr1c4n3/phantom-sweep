import abc
from typing import Dict
from phantom_sweep.core import ScanContext

class ScannerBase(abc.ABC):
    @abc.abstractmethod
    def scan(self, target: str, context: ScanContext ) -> Dict[str,any]:
        pass
        