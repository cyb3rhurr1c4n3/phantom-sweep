"""
ScriptingBase - Base class for all scripting plugins
"""
from abc import ABC, abstractmethod
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class ScriptingBase(ABC):

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
    def run(self, context: ScanContext, result: ScanResult) -> None:
        pass