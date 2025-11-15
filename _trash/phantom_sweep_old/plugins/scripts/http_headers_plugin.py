from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
import requests

class HttpHeaders(BasePlugin):
    def name(self):
        return "http-headers"
    
    def plugin_type(self):
        return PluginType.Analyze
    
    def register_cli(self, parse: ArgumentParser):
        return super().register_cli(parse)
    
    def _get_robots_txt(self, target: str, port: int) -> Dict[str, any]:
        result = {}
        try:
            res = requests.get(f"http://{target}:{port}/")
            # res = requests.get(f"https://{target}:{port}/")
            if res.status_code == 200:
                headers = res.headers
                result["http-headers"] = headers
        except Exception as e:
                result["http-headers"] = {"error": f"Exception occurred: {str(e)}"}
        return result
        
        

    def run(self, context: ScanContext, args):
        return super().run(context, args)
    