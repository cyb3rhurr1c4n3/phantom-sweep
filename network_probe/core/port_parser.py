"""
Port Parser - Parse port specifications like top_100, all, ranges, etc.
"""
from typing import List, Set
from network_probe.plugins.scanners.ping_scanner_plugin import Fast_Scan_Port


def parse_port_spec(port_spec: str) -> List[int]:
    """
    Parse port specification string.
    
    Supported formats:
    - "top_100" or "top_1000" - Common ports
    - "all" - All 65535 ports
    - "80,443,8080" - Comma-separated ports
    - "1-1000" - Port range
    - "80,443,1-100" - Mixed format
    """
    if not port_spec:
        return Fast_Scan_Port  # Default to top 100
    
    port_spec = port_spec.strip().lower()
    
    # Special cases
    if port_spec == "top_100":
        return Fast_Scan_Port
    elif port_spec == "top_1000":
        # Top 1000 common ports (simplified - using top 100 for now)
        return Fast_Scan_Port
    elif port_spec == "all":
        return list(range(1, 65536))
    
    # Parse comma-separated and ranges
    ports: Set[int] = set()
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        if '-' in part:
            # Range
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 0 < port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports)) if ports else Fast_Scan_Port


def parse_exclude_ports(exclude_spec: str, ports: List[int]) -> List[int]:
    """Exclude specified ports from the port list"""
    if not exclude_spec:
        return ports
    
    exclude_ports: Set[int] = set()
    parts = exclude_spec.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end <= 65535:
                    exclude_ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 0 < port <= 65535:
                    exclude_ports.add(port)
            except ValueError:
                continue
    
    return [p for p in ports if p not in exclude_ports]

