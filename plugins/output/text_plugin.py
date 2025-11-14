"""
Text Output Plugin - Output results in plain text format
"""
import json
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.Output.normal_plugin import NormalOutputPlugin


class TextPlugin(BasePlugin):
    """Text output plugin"""
    
    def name(self) -> str:
        return "text"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Output
    
    def metadata(self):
        return {
            "name": "text",
            "display_name": "Text Output",
            "description": "Output results in plain text format",
            "category": "output",
            "requires_root": False,
            "aliases": ["txt", "normal"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Generate text output"""
        output_format = getattr(args, 'output', 'text')
        if output_format != 'text':
            return {}
        
        output_file = getattr(args, 'output_file', None)
        if not output_file:
            # If no output file, results are printed to console by CLI
            return {}
        
        # Use existing NormalOutputPlugin for text output
        normal_plugin = NormalOutputPlugin()
        # Set output_normal in args for compatibility
        args.output_normal = output_file
        normal_plugin.run(context, args)
        return {}

