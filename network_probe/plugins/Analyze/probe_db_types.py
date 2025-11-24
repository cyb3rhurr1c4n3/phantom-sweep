import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Pattern, Callable

@dataclass
class MatchRule:
    """ Đại diện cho một dòng 'match' hoặc 'softmatch' """
    service_name: str
    pattern: Pattern[bytes]  # Regex đã được biên dịch (compiled)
    version_info: Dict[str, str] = field(default_factory=dict) # p, v, i, h, o
    is_softmatch: bool = False

@dataclass
class ServiceProbe:
    """ Đại diện cho một khối 'Probe ...' """
    protocol: str  # TCP hoặc UDP
    name: str      # Tên probe (ví dụ: NULL, GetReq)
    probe_string: bytes # Dữ liệu thô để gửi
    totalwaitms: int = 5000
    tcpwrappedms: int = 3000
    
    # Danh sách các cổng mà probe này phù hợp
    ports: set[int] = field(default_factory=set)
    # Các quy tắc match cho probe này
    matches: List[MatchRule] = field(default_factory=list)