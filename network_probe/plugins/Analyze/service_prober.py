# network_probe/plugins/analysis/service_prober.py
import socket
from typing import Dict, Any, List, Optional
from .probe_db_types import ServiceProbe, MatchRule
from .probe_parser import load_probe_database
class ServiceProber:
    """
    Engine thăm dò dịch vụ dựa trên CSDL của Nmap.
    """
    def __init__(self, context, probe_file_path: str):
        self.timeout = context.timeout
        self.debug = context.debug
        
        # Tải CSDL khi khởi tạo
        self.probes = load_probe_database(probe_file_path)
        
        # Tách probe NULL ra để dùng trước
        self.null_probe = next(p for p in self.probes if p.name == "NULL")
        
        # Sắp xếp các probe còn lại (logic ưu tiên)
        self.sorted_probes = sorted(
            [p for p in self.probes if p.name != "NULL"],
            key=lambda p: (len(p.ports) == 0, len(p.matches))
        )

    def _format_service_name(self, rule: MatchRule) -> str:
        """ Tạo chuỗi tên dịch vụ từ quy tắc đã khớp """
        info = rule.version_info
        parts = [info.get("p")] # Product
        parts.append(info.get("v")) # Version
        parts.append(info.get("i")) # Info
        
        # Lọc bỏ các giá trị None
        parts_str = ", ".join(filter(None, parts))
        
        if parts_str:
            return f"{rule.service_name} ({parts_str})"
        return rule.service_name

    def _check_matches(self, banner: bytes, rules: List[MatchRule]) -> Optional[str]:
        """ So khớp một banner với một danh sách các quy tắc """
        for rule in rules:
            match = rule.pattern.search(banner)
            if match:
                # Tìm thấy! (Bỏ qua softmatch cho đơn giản)
                if not rule.is_softmatch:
                    if self.debug:
                        print(f"  [DEBUG -sV] Đã khớp mạnh: {rule.service_name}")
                    return self._format_service_name(rule)
        return None

    def probe(self, target_ip: str, port: int, protocol: str = "TCP") -> str:
        """
        Thực hiện chuỗi probe hoàn chỉnh trên một cổng.
        """
        if protocol != "TCP":
            return "unknown (UDP not supported)" # (Prober UDP phức tạp hơn)
        
        # Xử lý các cổng đã biết
        if port == 443: return "https (SSL)"
        
        banner_data = b"" # Dữ liệu tích lũy
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout * 2) # Cho -sV thêm thời gian
                s.connect((target_ip, port))
                
                # 1. Thử Probe NULL (chỉ nghe)
                if self.debug:
                    print(f"  [DEBUG -sV] Thử NULL probe trên cổng {port}")
                try:
                    banner_data = s.recv(2048)
                except socket.timeout:
                    pass # Không có banner, không sao
                
                if banner_data:
                    # Kiểm tra xem banner có khớp với quy tắc NULL không
                    service = self._check_matches(banner_data, self.null_probe.matches)
                    if service:
                        return service # Tìm thấy! Xong.

                # 2. Không khớp NULL, bắt đầu lặp qua các probe khác
                
                # Ưu tiên các probe dựa trên cổng
                probes_to_try = [p for p in self.sorted_probes if port in p.ports]
                probes_to_try += [p for p in self.sorted_probes if port not in p.ports]
                
                for probe in probes_to_try:
                    if probe.protocol != "TCP": continue
                    
                    if self.debug:
                        print(f"  [DEBUG -sV] Thử probe '{probe.name}' trên cổng {port}")
                    
                    try:
                        # Gửi probe
                        s.sendall(probe.probe_string)
                        # Nhận thêm dữ liệu
                        more_data = s.recv(2048)
                        banner_data += more_data
                    except socket.timeout:
                        continue # Hết giờ, thử probe tiếp
                    except Exception:
                        break # Cổng bị đóng, dừng lại
                    
                    # Kiểm tra xem dữ liệu *tích lũy* có khớp không
                    service = self._check_matches(banner_data, probe.matches)
                    if service:
                        return service # Tìm thấy! Xong.

        except Exception as e:
            if self.debug:
                print(f"  [DEBUG -sV] Lỗi kết nối cổng {port}: {e}")
            return "unknown (conn-error)"

        # Không có probe nào khớp
        if banner_data:
            try:
                text = banner_data.decode('latin-1', 'ignore').split('\n')[0].strip()
                if text:
                    return text # Trả về dòng đầu tiên của banner
            except: pass
            
        return "unknown"