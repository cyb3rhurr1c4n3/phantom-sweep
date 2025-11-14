"""
None Ping Plugin - Skip host discovery, assume all hosts are up
"""
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class NonePlugin(BasePlugin):
    """No ping plugin - skip host discovery"""
    
    def name(self) -> str:
        return "none"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def metadata(self):
        return {
            "name": "none",
            "display_name": "No Host Discovery",
            "description": "Skip host discovery, assume all hosts are up",
            "category": "ping_tech",
            "requires_root": False,
            "aliases": ["skip", "no_ping"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Skip host discovery - mark all targets as up"""
        ping_method = getattr(args, 'ping_tech', 'icmp')
        if ping_method != 'none':
            return {}
        
        # Mark all targets as up
        scan_result = {}
        for target in context.targets:
            scan_result[target] = {
                "state": "up",
                "ports": {}
            }
        
        context.set_data("scan_results", scan_result)
        context.set_data("host_discovery", scan_result)
        print(f"[*] Bỏ qua host discovery, giả định tất cả host đều sống.")
        return scan_result

