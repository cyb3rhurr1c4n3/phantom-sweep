from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
import requests

class HttpRobotsTxt(BasePlugin):
    def name(self):
        return "http-robots"
    
    def plugin_type(self):
        return PluginType.Analyze
    
    def register_cli(self, parse: ArgumentParser):
        return super().register_cli(parse)
    
    def _get_robots_txt(self, target: str, port: int) -> Dict[str, any]:
        result = {}
        try:
            res = requests.get(f"http://{target}:{port}/robots.txt")
            # res = requests.get(f"https://{target}:{port}/robots.txt")
            if res.status_code == 200:
                data = res.content
                text = data.decode('utf-8')
                result["http-robots.txt"] = self._parse_robots(text)
        except Exception as e:
                result["http-robots.txt"] = f"Error while processing: {e}"
        return result
        
    def _parse_robots(self, content: str):
        """Parse disallowed entries from robots.txt content."""
        disallowed = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("disallow:"):
                # Extract after "Disallow:"
                entry = line.split(":", 1)[1].strip()
                # Remove comments inline
                entry = entry.split("#", 1)[0].strip()
                if entry and entry not in disallowed:
                    disallowed.append(entry)
        return disallowed        

    def run(self, context: ScanContext, args):
        return super().run(context, args)
    

# TODO 2: HTTP / HTTPS redirection???