from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType
from .service_prober import ServiceProber # Đã được viết lại
import socket
import os # Import os

# Định nghĩa đường dẫn đến CSDL (giả sử nó nằm cùng thư mục)
PROBE_DB_FILE = os.path.join(os.path.dirname(__file__), "nmap-service-probes.db") # Đổi tên file này

class ServiceScanPlugin(BasePlugin):
    
    def __init__(self):
        # Khởi tạo prober MỘT LẦN khi tải plugin
        self.prober = None

    def name(self) -> str:
        return "service_scan"
    
    def plugin_type(self)->PluginType:
        return PluginType.Analyze
    def register_cli(self, parse):
        pass

    def run(self, context: ScanContext, args):
        if not context.service_version:
            return 

        print(f"[*] Khởi chạy Service/Version Detection (-sV)...")
        
        # 1. Khởi tạo Prober (lazy-load)
        if not self.prober:
            # === SỬA ĐỔI QUAN TRỌNG ===
            # Bạn cần tải file CSDL của mình (đổi tên nếu cần)
            db_path = os.path.join(os.path.dirname(__file__), "nmap-service-probes.db")
            if not os.path.exists(db_path):
                print(f"[!] Lỗi -sV: Không tìm thấy file CSDL probe tại {db_path}")
                return
            try:
                self.prober = ServiceProber(context, db_path)
            except Exception as e:
                print(f"[!] Lỗi -sV: Không thể tải CSDL probe: {e}")
                return
            
        scan_results = context.get_data("scan_results")
        if not scan_results:
            print("[*] -sV: Không có kết quả scan TCP, bỏ qua.")
            return

        # 3. Lặp qua từng target
        for target, data in scan_results.items():
            # ... (logic lặp qua cổng giữ nguyên) ...
            
            try:
                ip_target = socket.gethostbyname(target)
            except socket.gaierror:
                continue 

            print(f"[*] Đang quét dịch vụ trên {target} ({ip_target})")

            for port, details in list(data.get("ports", {}).items()):
                if "open" in details.get("state", "").lower():
                    
                    # === SỬA ĐỔI QUAN TRỌNG ===
                    service_name = self.prober.probe(ip_target, port, "TCP")
                    
                    scan_results[target]["ports"][port]["service"] = service_name
        
        context.set_data("scan_results", scan_results)
        print(f"[*] Service/Version Detection hoàn tất.")