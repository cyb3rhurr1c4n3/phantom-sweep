"""
ScriptingBase - Base class for all scripting plugins
"""
from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ScriptingBase(ABC):
    """
    Base class for all scripting plugins (Extension scripts).
    All scripting implementations must inherit from this class.
    """
    
    @abstractmethod
    def name(self) -> str:
        """
        Return the name/identifier of this script.
        
        Returns:
            str: Script name (e.g., "ftp_anon", "http_risky", "ssl_check")
        """
        pass
    
    @abstractmethod
    def run(self, context: ScanContext, result: ScanResult) -> None:
        """
        Execute the script and update the ScanResult object.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult object to update with script results
        """
        pass
    
    def get_description(self) -> str:
        """
        Return a description of this script.
        Override in subclasses for custom descriptions.
        
        Returns:
            str: Script description
        """
        return f"Script: {self.name()}"

