from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
import requests
from bs4 import BeautifulSoup

class HttpTitle(BasePlugin):
    def name(self):
        return "http-title"
    
    def plugin_type(self):
        return PluginType.Analyze
    
    def register_cli(self, parse: ArgumentParser):
        return super().register_cli(parse)
    
    def _get_title(self, target: str, port: int) -> Dict[str, any]:
        result = {}
        try:
            res = requests.get(f"http://{target}:{port}")
            html_data = res.content
            html_text = html_data.decode('utf-8')
            soup = BeautifulSoup(html_text, 'html.parser')
            if not soup.title:
                title = ""
            else:
                title = soup.title.string
            result["http-title"] = title
        except Exception as e:
            result["http-title"] = f"Exception occurred: {str(e)}"
        
        return result
        
        
            

    def run(self, context: ScanContext, args):
        return super().run(context, args)
    

# TODO 2: HTTP / HTTPS redirection???