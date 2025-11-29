"""
Parsers for targets and ports specifications.
"""
import ipaddress    
import re
from typing import List, Set
import os
import socket
from phantom_sweep.core.constants import TOP_100_PORTS, TOP_1000_PORTS

def resolve_domain_to_ip(domain: str) -> str:
    """
    Resolve domain name to IP address.
    
    Args:
        domain: Domain name (e.g., scanme.nmap.org)
        
    Returns:
        str: IP address if successful, otherwise return the original domain
    """
    try:
        # Use socket.gethostbyname() to resolve domain
        ip = socket.gethostbyname(domain)
        return ip
    except (socket.gaierror, socket.error, OSError):
        # If resolution fails, return original domain
        return domain

def parse_port_spec(port_spec: str, port_list_file: str = None) -> List[int]:
    """
    Parse port specification string.
    
    Supported formats:
    - "top_100" - Top 100 most common ports
    - "top_1000" - Top 1000 most common ports
    - "all" - All 65535 ports
    - "80,443,8080" - Comma-separated ports
    - "1-1000" - Port range
    - "80,443,1-100" - Mixed format
    
    Args:
        port_spec: Port specification string
        port_list_file: Optional file path to read ports from (one per line)
        
    Returns:
        List[int]: Sorted list of port numbers
    """
    ports: Set[int] = set()
    
    # Read from file if provided
    if port_list_file and os.path.isfile(port_list_file):
        try:
            with open(port_list_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line.isdigit():
                        port = int(line)
                        if 0 < port <= 65535:
                            ports.add(port)
        except Exception:
            pass  # If file read fails, continue with port_spec parsing
    
    if not port_spec:
        return sorted(list(ports)) if ports else TOP_100_PORTS
    
    port_spec = port_spec.strip().lower()
    
    # Special cases
    if port_spec == "top_100":
        ports.update(TOP_100_PORTS)
    elif port_spec == "top_1000":
        ports.update(TOP_1000_PORTS)
    elif port_spec == "all":
        ports.update(range(1, 65536))
    else:
        # Parse comma-separated and ranges
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
    
    return sorted(list(ports)) if ports else TOP_100_PORTS

def parse_exclude_ports(exclude_spec: List[str], ports: List[int]) -> List[int]:
    """
    Exclude specified ports from the port list.
    
    Args:
        exclude_spec: List of port specifications to exclude (can be list of strings like ["21", "22,23", "top_100"])
                      Each string follows the same format as parse_port_spec
        ports: List of ports to filter
        
    Returns:
        List[int]: Filtered list of ports
    """
    if not exclude_spec:
        return ports
    
    exclude_ports: Set[int] = set()
    
    # Handle both single string and list of strings
    if isinstance(exclude_spec, str):
        exclude_spec = [exclude_spec]
    
    # Parse each exclude specification
    for spec in exclude_spec:
        if spec:
            exclude_ports.update(parse_port_spec(spec))
    
    return [p for p in ports if p not in exclude_ports]

def is_domain(target):
    pattern = r"^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
    return re.match(pattern,target) is not None

def parse_targets(targets: List[str]) -> List[str]:
    """
    Build target list from various formats.
    
    Supported formats:
    - Single IP: 192.168.1.1
    - Multiple IPs: 192.168.1.1 192.168.1.2
    - IP range (short): 192.168.1.1-100
    - IP range (full): 192.168.1.1-192.168.1.100
    - CIDR: 192.168.1.0/24
    - Domain: scanme.nmap.org (will be resolved to IP)
    """
    result = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        if is_domain(target):
            ip=resolve_domain_to_ip(target)
            result.append(ip)
            continue
        if '/' in target:
            # CIDR
            try:
                network = ipaddress.ip_network(target, strict=False)
                result.extend([str(ip) for ip in network])
            except ValueError:
                # If not a valid CIDR, try to resolve as domain
                ip = resolve_domain_to_ip(target)
                if ip != target:
                    result.append(ip)
                else:
                    result.append(target)
        elif '-' in target:
            # IP range - check if it's full format (192.168.1.1-192.168.1.100) or short (192.168.1.1-100)
            if target.count('.') >= 6:  # Full format: has dots on both sides of -
                # Full format: 192.168.1.1-192.168.1.100
                try:
                    start_ip, end_ip = target.split('-', 1)
                    start_ip_obj = ipaddress.IPv4Address(start_ip.strip())
                    end_ip_obj = ipaddress.IPv4Address(end_ip.strip())
                    
                    # Generate all IPs in range
                    start_int = int(start_ip_obj)
                    end_int = int(end_ip_obj)
                    if start_int <= end_int:
                        for ip_int in range(start_int, end_int + 1):
                            result.append(str(ipaddress.IPv4Address(ip_int)))
                    else:
                        result.append(target)
                except (ValueError, ipaddress.AddressValueError):
                    result.append(target)
            elif target.count('.') == 3 and '-' in target:
                # Short format: 192.168.1.1-100
                parts = target.split('.')
                if '-' in parts[-1]:
                    base = '.'.join(parts[:-1])
                    try:
                        start, end = map(int, parts[-1].split('-'))
                        if start <= end:
                            for i in range(start, end + 1):
                                result.append(f"{base}.{i}")
                        else:
                            result.append(target)
                    except ValueError:
                        result.append(target)
                else:
                    result.append(target)
            else:
                result.append(target)
        else:
            # Single IP, domain, or other format
            # Try to parse as IP first
            try:
                ipaddress.IPv4Address(target)
                result.append(target)
            except (ValueError, ipaddress.AddressValueError):
                # Not a valid IP, try to resolve as domain
                ip = resolve_domain_to_ip(target)
                result.append(ip)
    
    return result

def parse_exclude_hosts(exclude_spec: List[str], hosts: List[str]) -> List[str]:
    """
    Exclude specified hosts from the host list.
    
    Args:
        exclude_spec: List of host specifications to exclude (can be list of strings like ["192.168.1.5", "192.168.1.10-20"])
                      Each string follows the same format as parse_targets (IP, CIDR, range, etc.)
        hosts: List of hosts to filter
        
    Returns:
        List[str]: Filtered list of hosts
    """
    if not exclude_spec:
        return hosts
    
    # Handle both single string and list of strings
    if isinstance(exclude_spec, str):
        exclude_spec = [exclude_spec]
    
    # Parse all exclude targets (expand CIDR, ranges, etc.)
    exclude_hosts = parse_targets(exclude_spec)
    exclude_set = set(exclude_hosts)
    
    # Filter out excluded hosts
    return [h for h in hosts if h not in exclude_set]
