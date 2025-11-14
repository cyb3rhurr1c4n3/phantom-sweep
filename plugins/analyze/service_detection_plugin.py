"""
Service Detection Plugin - Detect services running on open ports
"""
import os
import socket
from argparse import ArgumentParser
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
from network_probe.plugins.Analyze.service_prober import ServiceProber


class ServiceDetectionPlugin(BasePlugin):
    """Service detection plugin"""
    
    def __init__(self):
        self.prober = None
    
    def name(self) -> str:
        return "service_detection"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Analyze
    
    def metadata(self):
        return {
            "name": "service_detection",
            "display_name": "Service Detection",
            "description": "Detect services running on open ports",
            "category": "analyze",
            "requires_root": False,
            "aliases": ["service", "version"]
        }
    
    def register_cli(self, parse: ArgumentParser):
        pass
    
    def run(self, context: ScanContext, args) -> dict:
        """Run service detection"""
        service_mode = getattr(args, 'service_detection_mode', 'ai')
        if service_mode == 'off':
            return {}
        
        print(f"[*] Khởi chạy Service Detection (mode: {service_mode})...")
        
        # Initialize prober if needed
        if service_mode == 'normal' and not self.prober:
            db_path = os.path.join(os.path.dirname(__file__), "nmap-service-probes.db")
            if os.path.exists(db_path):
                try:
                    self.prober = ServiceProber(context, db_path)
                except Exception as e:
                    print(f"[!] Lỗi: Không thể tải CSDL probe: {e}")
                    return {}
        
        scan_results = context.get_data("scan_results")
        if not scan_results:
            print("[*] Không có kết quả scan, bỏ qua service detection.")
            return {}
        
        # Process each target
        for target, data in scan_results.items():
            try:
                ip_target = socket.gethostbyname(target)
            except socket.gaierror:
                continue
            
            print(f"[*] Đang phát hiện dịch vụ trên {target} ({ip_target})")
            
            for port, details in list(data.get("ports", {}).items()):
                if "open" in details.get("state", "").lower():
                    if service_mode == 'normal' and self.prober:
                        service_name = self.prober.probe(ip_target, port, "TCP")
                        scan_results[target]["ports"][port]["service"] = service_name
                    elif service_mode == 'ai':
                        # AI mode - placeholder for future AI implementation
                        scan_results[target]["ports"][port]["service"] = "unknown"
        
        context.set_data("scan_results", scan_results)
        print(f"[*] Service Detection hoàn tất.")
        return scan_results

