# Ngữ cảnh quét 
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanContext:
    """Represents the scan configuration context"""
    targets: List[str]
    scan_type: str
    ports: Optional[str]
    scan_all_ports: bool
    fast_scan: bool
    service_version: bool
    os_detection: bool
    timing: int
    threads: int
    timeout: float
    output_normal: Optional[str]
    output_xml: Optional[str]
    output_json: Optional[str]
    output_html: Optional[str]
    show_open_only: bool
    verbose: bool
    debug: bool
    exclude: Optional[List[str]]
    input_list: Optional[str]
    
    # New fields for PhantomSweep CLI
    ping_tech: str = "icmp"
    scan_tech: str = "connect"
    service_detection_mode: str = "ai"
    os_fingerprinting_mode: str = "ai"
    rate: str = "balanced"
    exclude_ports: Optional[str] = None
    output: str = "text"
    output_file: Optional[str] = None
    scripts: Optional[List[str]] = None
    evasion: Optional[List[str]] = None

    _data_bag: Dict[str,Any]=field(default_factory=dict)

    def set_data(self,key:str,value):
        self._data_bag[key]=value

    def get_data(self,key:str)->Optional[Any]:
        return self._data_bag.get(key)