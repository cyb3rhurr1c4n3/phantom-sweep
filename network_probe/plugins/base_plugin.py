
import abc
from typing import Dict, List
from network_probe.core.context import ScanContext
from argparse import ArgumentParser
from plugin_types import PluginType
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
    def run(self, context: ScanContext, args):
        pass
        