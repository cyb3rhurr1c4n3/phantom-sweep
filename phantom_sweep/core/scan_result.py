"""
ScanResult - Container for scan results
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class PortInfo:
    """Information about a scanned port"""
    port: int
    state: str  # open, closed, filtered, open|filtered
    protocol: str = "tcp"  # tcp or udp
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HostInfo:
    """Information about a scanned host"""
    host: str
    state: str = "unknown"  # up, down, unknown
    os: Optional[str] = None
    os_version: Optional[str] = "unknown"
    os_accuracy: Optional[int] = None
    tcp_ports: Dict[int, PortInfo] = field(default_factory=dict)
    udp_ports: Dict[int, PortInfo] = field(default_factory=dict)
    scripts: Dict[str, Any] = field(default_factory=dict)  # Script results
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """
    Complete scan results container.
    Contains all information discovered during the scan.
    """
    hosts: Dict[str, HostInfo] = field(default_factory=dict)
    
    # Scan metadata
    scan_start_time: Optional[str] = None
    scan_end_time: Optional[str] = None
    scan_duration: Optional[float] = None
    
    # Statistics
    total_hosts: int = 0
    up_hosts: int = 0
    total_ports_scanned: int = 0
    open_ports: int = 0
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_host(self, host: str, state: str = "up") -> HostInfo:
        """Add or get a host"""
        if host not in self.hosts:
            self.hosts[host] = HostInfo(host=host, state=state)
        return self.hosts[host]
    
    def get_host(self, host: str) -> Optional[HostInfo]:
        """Get host information"""
        return self.hosts.get(host)
    
    def add_port(self, host: str, port: int, state: str, protocol: str = "tcp", **kwargs) -> PortInfo:
        """Add port information to a host"""
        host_info = self.add_host(host)
        port_info = PortInfo(port=port, state=state, protocol=protocol, **kwargs)
        
        if protocol == "tcp":
            host_info.tcp_ports[port] = port_info
        else:
            host_info.udp_ports[port] = port_info
        
        return port_info
    
    def get_port(self, port: int) -> Optional[PortInfo]:
        """Implement this"""
        pass
    
    def get_discovered_hosts(self) -> List[str]:
        """Get list of discovered UP hosts"""
        return [h for h in self.hosts.keys() if self.hosts[h].state == "up"]
    
    def get_alive_hosts_count(self) -> int:
        """Get count of discovered alive hosts"""
        return sum(1 for h in self.hosts.values() if h.state == "up")
    
    def get_open_ports_count(self) -> int:
        """Get count of open ports found so far"""
        count = 0
        for host in self.hosts.values():
            count += sum(1 for p in host.tcp_ports.values() if p.state == "open")
            count += sum(1 for p in host.udp_ports.values() if p.state == "open")
        return count

    def update_statistics(self):
        """Update scan statistics"""
        self.total_hosts = len(self.hosts)
        self.up_hosts = sum(1 for h in self.hosts.values() if h.state == "up")
        
        total_ports = 0
        open_count = 0
        for host_info in self.hosts.values():
            total_ports += len(host_info.tcp_ports) + len(host_info.udp_ports)
            open_count += sum(1 for p in host_info.tcp_ports.values() if p.state == "open")
            open_count += sum(1 for p in host_info.udp_ports.values() if p.state == "open")
        
        self.total_ports_scanned = total_ports
        self.open_ports = open_count
    
    def get_all_open_ports(self) -> Dict[str, List[PortInfo]]:
        """Get all open ports grouped by host"""
        result = {}
        for host, host_info in self.hosts.items():
            open_ports = []
            open_ports.extend([p for p in host_info.tcp_ports.values() if p.state == "open"])
            open_ports.extend([p for p in host_info.udp_ports.values() if p.state == "open"])
            if open_ports:
                result[host] = open_ports
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "hosts": {
                host: {
                    "host": info.host,
                    "state": info.state,
                    "os": info.os,
                    "os_version": info.os_version,
                    "os_accuracy": info.os_accuracy,
                    "tcp_ports": {
                        port: {
                            "port": p.port,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "banner": p.banner,
                            **p.extra
                        }
                        for port, p in info.tcp_ports.items()
                    },
                    "udp_ports": {
                        port: {
                            "port": p.port,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "banner": p.banner,
                            **p.extra
                        }
                        for port, p in info.udp_ports.items()
                    },
                    "scripts": info.scripts,
                    **info.extra
                }
                for host, info in self.hosts.items()
            },
            "statistics": {
                "total_hosts": self.total_hosts,
                "up_hosts": self.up_hosts,
                "total_ports_scanned": self.total_ports_scanned,
                "open_ports": self.open_ports
            },
            "metadata": {
                "scan_start_time": self.scan_start_time,
                "scan_end_time": self.scan_end_time,
                "scan_duration": self.scan_duration,
                **self.metadata
            }
        }
