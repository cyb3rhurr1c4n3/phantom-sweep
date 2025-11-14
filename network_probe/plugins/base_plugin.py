
import abc
from typing import Dict, List, Optional
from network_probe.core.context import ScanContext
from argparse import ArgumentParser
from network_probe.plugins.plugin_types import PluginType
class BasePlugin(abc.ABC):
    @abc.abstractmethod
    def name(self)-> str:
        pass

    @abc.abstractmethod
    def plugin_type(self) -> PluginType:
        pass

    @abc.abstractmethod
    def register_cli(self, parse: ArgumentParser):
        pass

    @abc.abstractmethod
    def run(self, context: ScanContext, args) -> Dict[str, any]:
        pass
    
    def metadata(self) -> Optional[Dict[str, any]]:
        """
        Return plugin metadata. Override this method in subclasses.
        Returns a dict with keys: name, display_name, description, category, requires_root, aliases
        """
        return {
            "name": self.name(),
            "display_name": self.name(),
            "description": "",
            "category": "",
            "requires_root": False,
            "aliases": []
        }

class BaseReport(abc.ABC):
    @abc.abstractmethod
    def save(self, results: Dict[str,any],filename: str):
        pass

class BaseScanner(abc.ABC):
    @abc.abstractmethod
    def scan(self, targets: List[str], context: ScanContext, args=None) -> Dict[str,any]:
        """Run the scanner against a batch of targets"""
        pass
        