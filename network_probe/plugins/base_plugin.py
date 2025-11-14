
import abc
from typing import Dict, List
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

class BaseReport(abc.ABC):
    @abc.abstractmethod
    def save(self, results: Dict[str,any],filename: str):
        pass

class BaseScanner(abc.ABC):
    @abc.abstractmethod
    def scan(self, targets: List[str], context: ScanContext, args=None) -> Dict[str,any]:
        """Run the scanner against a batch of targets"""
        pass
        