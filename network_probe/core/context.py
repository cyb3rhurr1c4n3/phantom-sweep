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

    _data_bag: Dict[str,Any]=field(default_factory=dict)

    def set_data(self,key:str,value):
        self._data_bag[key]=value

    def get_data(self,key:str)->Optional[Any]:
        self._data_bag.get(key)