from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType

class HttpTitle(BasePlugin):
    def name(self):
        return "http.title"
    
    def plugin_type(self):
        return PluginType.Analyze
    
    def register_cli(self, parse: ArgumentParser):
        return super().register_cli(parse)
    
    def run(self, context: ScanContext, args):
        return super().run(context, args)