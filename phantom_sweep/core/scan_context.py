from dataclasses import dataclass, field
from typing import List, Optional


# ========== Input Configuration ==========
@dataclass
class TargetConfig:
    """Target specification configuration"""
    host: List[str] = field(default_factory=list)
    host_list: Optional[str] = None
    exclude_host: List[str] = field(default_factory=list)


@dataclass
class PortConfig:
    """Port specification configuration"""
    port: str = "top_100"
    port_list: Optional[str] = None
    exclude_port: Optional[List[str]] = None


@dataclass
class PipelineConfig:
    """Scan pipeline configuration"""
    ping_tech: str = "icmp"
    scan_tech: str = "connect"
    service_detection_mode: str = "off"
    os_fingerprinting_mode: str = "off"
    script: List[str] = field(default_factory=list)


@dataclass
class PerformanceConfig:
    """Performance and evasion techniques configuration"""
    rate: str = "balanced"
    thread: int = 50
    timeout: float = 1.0
    evasion_mode: List[str] = field(default_factory=list)


@dataclass
class OutputConfig:
    """Output configuration"""
    output_format: str = "none"
    output_filename: Optional[str] = None


@dataclass
class ScanContext:
    targets: TargetConfig = field(default_factory=TargetConfig)
    ports: PortConfig = field(default_factory=PortConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    verbose: bool = False
    debug: bool = False
    open_only: bool = True