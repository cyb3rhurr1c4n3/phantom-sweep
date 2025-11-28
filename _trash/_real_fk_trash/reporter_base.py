"""
ReporterBase - Base class for all reporter plugins
"""
from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ReporterBase(ABC):
    """
    Base class for all reporter plugins (Output formatters).
    All reporter implementations must inherit from this class.
    """
    
    @abstractmethod
    def name(self) -> str:
        """
        Return the name/identifier of this reporter.
        
        Returns:
            str: Reporter name (e.g., "json", "xml", "text", "csv")
        """
        pass
    
    @abstractmethod
    def export(self, context: ScanContext, result: ScanResult, filename: str = None) -> None:
        """
        Export scan results in the specified format.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult object containing scan results
            filename: Optional filename to save output. If None, print to console.
        """
        pass
    
    def get_description(self) -> str:
        """
        Return a description of this reporter.
        Override in subclasses for custom descriptions.
        
        Returns:
            str: Reporter description
        """
        return f"Reporter: {self.name()}"

