

from abc import ABC, abstractmethod

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class AnalyzerBase(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        pass
    @property
    @abstractmethod
    def description(self) -> str:
        pass
    @property
    @abstractmethod
    def analyze(self, context: ScanContext, result: ScanResult):
        pass
