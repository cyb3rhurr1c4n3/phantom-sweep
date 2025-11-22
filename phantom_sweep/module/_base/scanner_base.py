"""
ScannerBase - Base class for all scanner plugins
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ScannerBase(ABC):
    """
    Base class for all scanner plugins.
    All scanner implementations must inherit from this class.
    """
    
    @abstractmethod
    def name(self) -> str:
        """
        Return the name/identifier of this scanner.
        
        Returns:
            str: Scanner name (e.g., "icmp_ping", "tcp_syn_scan")
        """
        pass
    
    @abstractmethod
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Execute the scan and update the ScanResult object.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult object to update with scan results
        """
        pass
    
    def requires_root(self) -> bool:
        """
        Check if this scanner requires root privileges.
        Override in subclasses if root is required.
        
        Returns:
            bool: True if root privileges are required, False otherwise
        """
        return False
    
    def get_description(self) -> str:
        """
        Return a description of this scanner.
        Override in subclasses for custom descriptions.
        
        Returns:
            str: Scanner description
        """
        return f"Scanner: {self.name()}"

