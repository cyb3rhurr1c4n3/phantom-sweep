"""
AnalyzerBase - Base class for all analyzer plugins
"""
from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class AnalyzerBase(ABC):
    """
    Base class for all analyzer plugins (Service Detection, OS Fingerprinting).
    All analyzer implementations must inherit from this class.
    """
    
    @abstractmethod
    def name(self) -> str:
        """
        Return the name/identifier of this analyzer.
        
        Returns:
            str: Analyzer name (e.g., "service_detection_normal", "os_fingerprinting_ai")
        """
        pass
    
    @abstractmethod
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """
        Execute the analysis and update the ScanResult object.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult object to update with analysis results
        """
        pass
    
    def get_description(self) -> str:
        """
        Return a description of this analyzer.
        Override in subclasses for custom descriptions.
        
        Returns:
            str: Analyzer description
        """
        return f"Analyzer: {self.name()}"

