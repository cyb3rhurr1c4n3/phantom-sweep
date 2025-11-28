"""
AnalyzerBase - Base class for all analyzer plugins
"""
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
    def type(self) -> str:
        pass

    @abstractmethod
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        pass
    
    def get_description(self) -> str:
        """
        Return a description of this analyzer.
        Override in subclasses for custom descriptions.
        
        Returns:
            str: Analyzer description
        """
        return f"Analyzer: {self.name()}"

