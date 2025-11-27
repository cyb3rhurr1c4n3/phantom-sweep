"""
Base schema for writing plugin. Every plugin have to implement the abstract method for it to work with the app
"""
from phantom_sweep.module._base.scanner_base import ScannerBase
from phantom_sweep.module._base.scripting_base import ScriptingBase

__all__ = ['ScannerBase', 'ScriptingBase']

