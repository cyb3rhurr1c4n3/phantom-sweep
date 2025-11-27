from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ReporterBase(ABC):

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

    def register_cli(self, parser) -> None:
        pass

    @abstractmethod
    def export(self, context: ScanContext, result: ScanResult, filename: str = None) -> None:
        pass