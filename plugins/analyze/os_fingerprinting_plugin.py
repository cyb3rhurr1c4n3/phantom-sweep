"""
OS Fingerprinting Plugin - Detect operating system of target hosts
"""
import socket
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class OsFingerprintingPlugin(BasePlugin):
    """OS fingerprinting plugin"""
    
    def name(self) -> str:
        return "os_fingerprinting"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Analyze
    
    def metadata(self):
        return {
            "name": "os_fingerprinting",
            "display_name": "OS Fingerprinting",
            "description": "Detect operating system of target hosts",
            "category": "analyze",
            "requires_root": False,
            "aliases": ["os", "os_detection"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run OS fingerprinting"""
        os_mode = getattr(args, 'os_fingerprinting_mode', 'ai')
        if os_mode == 'off':
            return {}
        
        print(f"[*] Khởi chạy OS Fingerprinting (mode: {os_mode})...")
        
        scan_results = context.get_data("scan_results")
        if not scan_results:
            print("[*] Không có kết quả scan, bỏ qua OS fingerprinting.")
            return {}
        
        # Process each target
        for target, data in scan_results.items():
            try:
                ip_target = socket.gethostbyname(target)
            except socket.gaierror:
                continue
            
            print(f"[*] Đang phát hiện OS trên {target} ({ip_target})")
            
            if os_mode == 'normal':
                # Normal mode - basic TTL/Window size detection
                # Placeholder for basic detection
                scan_results[target]["os"] = "Unknown"
            elif os_mode == 'ai':
                # AI mode - placeholder for future AI implementation
                scan_results[target]["os"] = "Unknown (AI mode)"
        
        context.set_data("scan_results", scan_results)
        print(f"[*] OS Fingerprinting hoàn tất.")
        return scan_results

