from dataclasses import dataclass, field
from typing import List, Optional, Set

# ==================== Mini Class ====================

@dataclass
class TargetConfig:
    """Lưu trữ cấu hình MỤC TIÊU (từ --host, --input-file, --exclude)"""
    # Lưu các mục tiêu được chỉ định rõ ràng
    hosts: List[str] = field(default_factory=list) 
    # Lưu đường dẫn file, Manager sẽ xử lý việc đọc file
    input_file: Optional[str] = None 
    # Lưu các mục tiêu cần loại trừ
    exclude_hosts: List[str] = field(default_factory=list)

@dataclass
class PortConfig:
    """Lưu trữ cấu hình CỔNG (từ --port)"""
    # Lưu chuỗi đặc tả cổng (ví dụ: "top_100", "all", "80,443,1000-2000")
    # Module Scanner sẽ tự phân giải chuỗi này
    spec: str = "top_100"
    exclude_ports: Optional[str] = None # Ví dụ: "8080,9090"

@dataclass
class PipelineConfig:
    """Lưu trữ cấu hình QUY TRÌNH QUÉT (Các bước 1-4)"""
    ping_tech: str = "icmp"  # (icmp, tcp, arp, none)
    scan_tech: str = "connect" # (connect, stealth, udp)
    
    # Đổi tên ngắn gọn hơn, rõ ràng đây là chế độ (mode)
    service_mode: str = "ai" # (ai, normal)
    os_mode: str = "ai"      # (ai, normal)

@dataclass
class PerformanceAndEvasionConfig:
    """Lưu trữ cấu hình HIỆU SUẤT & EVASION (từ --rate, --threads, --timeout)"""
    # 'stealthy' sẽ kích hoạt AI Adaptive Timing
    rate: str = "balanced" 
    threads: int = 10
    timeout: float = 1.0

@dataclass
class OutputConfig:
    """Lưu trữ cấu hình ĐẦU RA (từ --output, --output-file)"""
    format: str = "text" # (text, json, csv, xml)
    file: Optional[str] = None # Tên file, nếu None thì in ra stdout

@dataclass
class ExtensionConfig:
    """Lưu trữ cấu hình MỞ RỘNG (từ --script, --combo)"""
    scripts: List[str] = field(default_factory=list)
    combo: Optional[str] = None

# ==================== Big Class ====================

@dataclass
class ScanContext:
    """
    Đại diện cho toàn bộ cấu hình quét, được tạo ra bởi CLI Parser.
    Ánh xạ 1:1 với các tùy chọn CLI của PhantomSweep.
    """
    
    # Sử dụng các lớp con để nhóm cấu hình
    targets: TargetConfig
    ports: PortConfig
    pipeline: PipelineConfig
    performance: PerformanceAndEvasionConfig
    output: OutputConfig
    extensions: ExtensionConfig

    # Các cờ chung (Tùy chọn này không thuộc nhóm nào)
    verbose: bool = False
    debug: bool = False

    _data_bag: Dict[str,Any]=field(default_factory=dict)

    def set_data(self,key:str,value):
        self._data_bag[key]=value

    def get_data(self,key:str)->Optional[Any]:
        return self._data_bag.get(key)