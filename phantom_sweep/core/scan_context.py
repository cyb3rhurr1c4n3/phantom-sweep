"""
ScanContext - Configuration container for scan operations
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class TargetConfig:
    """Target configuration (from --host, --input-file, --exclude-ip)"""
    host: List[str] = field(default_factory=list)
    host_list: Optional[str] = None
    exclude_host: List[str] = field(default_factory=list)


@dataclass
class PortConfig:
    """Port configuration (from --port, --exclude-port)"""
    port: str = "top_100"  # "top_100", "top_1000", "all", or port specification like "80,443" or "1-1000"
    port_list: Optional[str] = None
    exclude_port: Optional[List[str]] = None  # Can be list of strings like ["21", "22,23", "top_100"]


@dataclass
class PipelineConfig:
    """Scan pipeline configuration (from --ping-tech, --scan-tech, --service-detection-mode, --os-fingerprinting-mode, --script)"""
    ping_tech: str = "icmp"  # icmp, tcp, arp, none
    scan_tech: str = "connect"  # connect, stealth, udp, none
    service_detection_mode: str = "ai"  # ai, normal, off
    os_fingerprinting_mode: str = "ai"  # ai, normal, off
    script: List[str] = field(default_factory=list) # find in scripting folder


@dataclass
class PerformanceAndEvasionConfig:
    """Performance and evasion configuration (from --rate, --threads, --timeout, --evasion)"""
    rate: str = "balanced"  # stealthy, balanced, fast, insane
    thread: int = 10
    timeout: float = 1.0
    evasion_mode: List[str] = field(default_factory=list)  # randomize, fragment, decoy, spoof


@dataclass
class OutputConfig:
    """Output configuration (from --output, --output-file)"""
    output_format: str = "none"  # text, json, xml, csv, comma-separated, or none (default)
    output_filename: Optional[str] = None


@dataclass
class ScanContext:
    """
    Complete scan configuration container.
    Groups related settings into logical config objects for better organization.
    """
    targets: TargetConfig = field(default_factory=TargetConfig)
    ports: PortConfig = field(default_factory=PortConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    performance: PerformanceAndEvasionConfig = field(default_factory=PerformanceAndEvasionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # Global flags
    verbose: bool = False
    debug: bool = False
    open_only: bool = True  # Only show open ports by default
    
    # Intermediate data storage (for temporary data during scan execution, NOT final results)
    # Final results should be stored in ScanResult, not here
    _intermediate_data: Dict[str, Any] = field(default_factory=dict, repr=False)
    
    def set_intermediate_data(self, key: str, value: Any) -> None:
        """Store intermediate/temporary data during scan execution"""
        self._intermediate_data[key] = value
    
    def get_intermediate_data(self, key: str, default: Any = None) -> Any:
        """Retrieve intermediate/temporary data"""
        return self._intermediate_data.get(key, default)

