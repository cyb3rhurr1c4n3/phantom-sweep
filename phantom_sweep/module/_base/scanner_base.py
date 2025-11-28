"""
ScannerBase - Base class for all scanner plugins
"""
from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ScannerBase(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def type(self) -> str:
        pass

    @property
    @abstractmethod 
    def description(self) -> str:
        pass

    def requires_root(self) -> bool:
        return False

    def register_cli(self, parser) -> None:
        pass

    @abstractmethod
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        pass