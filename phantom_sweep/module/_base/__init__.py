"""
Base schema for writing plugin. Every plugin have to implement the abstract method for it to work with the app
"""
from phantom_sweep.module._base.scanner_base import ScannerBase
from phantom_sweep.module._base.scripting_base import ScriptingBase
from phantom_sweep.module._base.reporter_base import ReporterBase
from phantom_sweep.module._base.analyzer_base import AnalyzerBase

__all__ = ['ScannerBase', 'ScriptingBase', 'ReporterBase', 'AnalyzerBase']

