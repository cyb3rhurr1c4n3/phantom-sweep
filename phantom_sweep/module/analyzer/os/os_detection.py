"""
OS Detection Scanner - Collect TCP/IP fingerprints for AI classification
Compatible with Random Forest model trained on Nmap-style features
"""
import asyncio
import socket
import struct
import time
from typing import Dict, Optional, List
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class OSDetectionScanner(ScannerBase):
    """OS Detection - Collect comprehensive fingerprints for ML classification"""
    
    @property
    def name(self) -> str:
        return "os_detect"
    
    @property
    def type(self) -> str:
        return "os_detection"
    
    @property
    def description(self) -> str:
        return "OS Detection via TCP/IP fingerprinting (AI-powered)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform OS detection on discovered hosts"""
        hosts = context.targets.host
        if not hosts:
            return
        
        # Get up hosts with open ports
        up_hosts = []
        for h in hosts:
            if h in result.hosts and result.hosts[h].state == "up":
                # Check if host has at least one open TCP port
                host_info = result.hosts[h]
                has_open_ports = (
                    any(p.state == "open" for p in host_info.tcp_ports.values()) or
                    any(p.state == "open" for p in host_info.udp_ports.values())
                )
                if has_open_ports:
                    up_hosts.append(h)
        
        if not up_hosts:
            if context.verbose:
                print("[*] No suitable hosts for OS detection (need open ports)")
            return
        
        if context.verbose:
            print(f"[*] Starting OS Detection on {len(up_hosts)} hosts...")
        
        for host in up_hosts:
            try:
                if context.verbose:
                    print(f"  [*] Fingerprinting {host}...")
                
                fingerprint = self._collect_fingerprint(host, result, context)
                
                # Add fingerprint to result (you'll need to add this method to ScanResult)
                if fingerprint:
                    # Store in result object
                    if not hasattr(result, 'os_fingerprints'):
                        result.os_fingerprints = {}
                    result.os_fingerprints[host] = fingerprint
                    
                    if context.verbose:
                        print(f"  [✓] Collected fingerprint from {host}")
                        print(f"      TTL: {fingerprint.get('ttl', 'N/A')}, "
                              f"Window: {fingerprint.get('window_size', 'N/A')}")
                
            except Exception as e:
                if context.debug:
                    print(f"  [!] OS detection error for {host}: {e}")
    
    def _collect_fingerprint(
        self, 
        host: str, 
        result: ScanResult,
        context: ScanContext
    ) -> Dict:
        """Collect comprehensive OS fingerprint (Nmap-style features)"""
        
        # Get open and closed ports
        open_ports = []
        closed_ports = []

        if host in result.hosts:
            host_info = result.hosts[host]
            # Get TCP ports
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    open_ports.append(port)
                elif port_info.state == "closed":
                    closed_ports.append(port)
            
            # Get UDP ports  
            for port, port_info in host_info.udp_ports.items():
                if port_info.state == "open":
                    open_ports.append(port)
                elif port_info.state == "closed":
                    closed_ports.append(port)
        
        fingerprint = {
            'host': host,
            'timestamp': time.time(),
            'open_ports': open_ports[:10],  # Limit to first 10
            'closed_ports': closed_ports[:5],
        }
        
        # TCP/IP Stack Fingerprinting
        tcp_fp = self._tcp_fingerprint(host, open_ports, closed_ports)
        fingerprint.update(tcp_fp)
        
        # ICMP Fingerprinting
        icmp_fp = self._icmp_fingerprint(host)
        fingerprint.update(icmp_fp)
        
        # Service Banner Grabbing
        banners = self._grab_banners(host, open_ports[:5])
        fingerprint['banners'] = banners
        
        # Extract features from banners
        banner_features = self._extract_banner_features(banners)
        fingerprint.update(banner_features)
        
        return fingerprint
    
    def _tcp_fingerprint(
        self, 
        host: str, 
        open_ports: List[int],
        closed_ports: List[int]
    ) -> Dict:
        """TCP/IP stack fingerprinting - Core OS detection features"""
        
        features = {
            'ttl': None,
            'window_size': None,
            'df_flag': None,
            'tcp_options': None,
            'ip_id_sequence': None,
            'tcp_timestamp': None,
        }
        
        try:
            # Test 1: SYN to open port (if available)
            if open_ports:
                target_port = open_ports[0]
                pkt = IP(dst=host)/TCP(
                    dport=target_port, 
                    flags="S", 
                    seq=12345,
                    options=[('MSS', 1460), ('NOP', None), ('WScale', 10)]
                )
                resp = sr1(pkt, timeout=2, verbose=0)
                
                if resp and resp.haslayer(TCP):
                    # TTL (most important feature)
                    features['ttl'] = resp[IP].ttl
                    
                    # Window Size (very important)
                    features['window_size'] = resp[TCP].window
                    
                    # DF Flag (Don't Fragment)
                    features['df_flag'] = 1 if resp[IP].flags.DF else 0
                    
                    # TCP Options
                    features['tcp_options'] = str(resp[TCP].options)
                    
                    # IP ID
                    features['ip_id'] = resp[IP].id
                    
                    # TCP Timestamp (if present)
                    for opt_name, opt_val in resp[TCP].options:
                        if opt_name == 'Timestamp':
                            features['tcp_timestamp'] = opt_val[0] if opt_val else None
                            break
            
            # Test 2: SYN to closed port (RST response)
            if closed_ports:
                target_port = closed_ports[0]
                pkt = IP(dst=host)/TCP(dport=target_port, flags="S", seq=54321)
                resp = sr1(pkt, timeout=2, verbose=0)
                
                if resp and resp.haslayer(TCP):
                    features['rst_ttl'] = resp[IP].ttl
                    features['rst_window'] = resp[TCP].window
            
            # Test 3: IP ID sequence (send multiple packets)
            if open_ports:
                ip_ids = []
                for i in range(3):
                    pkt = IP(dst=host)/TCP(dport=open_ports[0], flags="S", seq=10000+i)
                    resp = sr1(pkt, timeout=1, verbose=0)
                    if resp and resp.haslayer(IP):
                        ip_ids.append(resp[IP].id)
                    time.sleep(0.1)
                
                if len(ip_ids) >= 2:
                    # Check if incremental
                    diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
                    if all(0 < d < 10 for d in diffs):
                        features['ip_id_sequence'] = 'incremental'
                    elif all(d == 0 for d in diffs):
                        features['ip_id_sequence'] = 'constant'
                    else:
                        features['ip_id_sequence'] = 'random'
        
        except Exception as e:
            pass  # Silently fail, some features will be None
        
        return features
    
    def _icmp_fingerprint(self, host: str) -> Dict:
        """ICMP fingerprinting"""
        features = {
            'icmp_ttl': None,
            'icmp_code': None,
            'icmp_response': False,
        }
        
        try:
            # Send ICMP Echo Request
            pkt = IP(dst=host)/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            
            if resp:
                features['icmp_response'] = True
                features['icmp_ttl'] = resp[IP].ttl
                if resp.haslayer(ICMP):
                    features['icmp_code'] = resp[ICMP].code
        
        except Exception:
            pass
        
        return features
    
    def _grab_banners(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Grab service banners from common ports"""
        banners = {}
        
        # Common ports to grab banners from
        banner_ports = {
            21: ('FTP', b''),
            22: ('SSH', b''),
            25: ('SMTP', b'EHLO test\r\n'),
            80: ('HTTP', b'GET / HTTP/1.0\r\n\r\n'),
            443: ('HTTPS', b''),  # Would need SSL
            110: ('POP3', b''),
            143: ('IMAP', b''),
            3389: ('RDP', b''),
        }
        
        for port in ports:
            if port not in banner_ports:
                continue
            
            service_name, probe = banner_ports[port]
            banner = self._get_banner(host, port, probe, timeout=3)
            
            if banner:
                banners[port] = banner
        
        return banners
    
    def _get_banner(
        self, 
        host: str, 
        port: int, 
        probe: bytes = b'',
        timeout: int = 3
    ) -> Optional[str]:
        """Get banner from specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send probe if provided
            if probe:
                sock.send(probe)
            
            # Receive response
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner[:500] if banner else None
        
        except Exception:
            return None
    
    def _extract_ssh_version(self, banner_lower: str) -> str:
        try:
            first_part = banner_lower.split()[0]
            version = first_part.split("_")[1]
            return version[0:3]
        except:
            return ""

    openssh_ubuntu_version = {"6.6":"14.04", "7.2":"16.04", "7.6":"18.04", "8.2":"20.04", "8.9":"22.04", "9.6":"24.04"}
    openssh_debian_version = {"6.7":"8", "7.4":"9", "7.9":"10", "8.4":"11", "9.2":"12", "10.0":"13"}
    iis_windows_version = {"6.0":"Server 2003/Server 2003 R2", "7.0": "Server 2008", "7.5": "7/Server 2008 R2",
                                   "8.0":"Server 2012", "8.5":"8.1/Server 2012 R2", "10.0": "10/Server 2016/Server 2019/Server 2022/11/Server 2025"}

    def _extract_banner_features(self, banners: Dict[int, str]) -> Dict:
        """Extract ML features from service banners"""
        features = {
            'has_ssh': False,
            'has_http': False,
            'has_ftp': False,
            'has_smtp': False,
            'ssh_version': None,
            'http_server': None,
            'os_hint_from_banner': None,
            'possible_os_version': None
        }
        
        for port, banner in banners.items():
            banner_lower = banner.lower()
            
            # SSH detection
            if port == 22 or 'ssh' in banner_lower:
                features['has_ssh'] = True
                if 'openssh' in banner_lower:
                    features['ssh_version'] = 'OpenSSH'
                    # Extract OS hint
                    if 'ubuntu' in banner_lower:
                        features['os_hint_from_banner'] = 'Ubuntu'
                        try:
                            features['possible_os_version'] = self.openssh_ubuntu_version[self._extract_ssh_version(banner_lower)]
                        except Exception as e:
                            features['possible_os_version'] = f"unknown"
                    elif 'debian' in banner_lower:
                        features['os_hint_from_banner'] = 'Debian'
                        try:
                            features['possible_os_version'] = self.openssh_debian_version[self._extract_ssh_version(banner_lower)]
                        except Exception as e:
                            features['possible_os_version'] = f"unknown"
                    elif 'freebsd' in banner_lower:
                        features['os_hint_from_banner'] = 'FreeBSD'
                    elif 'openbsd' in banner_lower:
                        features['os_hint_from_banner'] = 'OpenBSD'
                    else:
                        features['os_hint_from_banner'] = 'Unknown'



            # HTTP detection
            if port in [80, 443, 8080] or 'http' in banner_lower:
                features['has_http'] = True
                if 'server:' in banner_lower:
                    # Extract server header
                    for line in banner.split('\n'):
                        if line.lower().startswith('server:'):
                            server = line.split(':', 1)[1].strip()
                            features['http_server'] = server[:100]
                            
                            # OS hints from server header
                            if 'ubuntu' in server.lower():
                                features['os_hint_from_banner'] = 'Ubuntu'
                            elif 'debian' in server.lower():
                                features['os_hint_from_banner'] = 'Debian'
                            elif 'win' in server.lower() or 'iis' in server.lower():
                                features['os_hint_from_banner'] = 'Windows'
                                if 'iis' in server.lower():
                                    try:
                                        version = server.lower().split("/")[1] # Server: Microsoft-IIS/10.0
                                        features['possible_os_version'] = self.iis_windows_version[version]
                                    except Exception as e:
                                        features['possible_os_version'] = "unknown"
                            else:
                                features['os_hint_from_banner'] = 'Unknown'
                            break
            
            # FTP detection
            if port == 21 or 'ftp' in banner_lower:
                features['has_ftp'] = True
            
            # SMTP detection
            if port == 25 or 'smtp' in banner_lower:
                features['has_smtp'] = True
        
        return features


# Helper function to save fingerprints to JSON for dataset creation
def save_fingerprints_to_json(result: ScanResult, filename: str):
    """Save collected fingerprints to JSON file for training dataset"""
    import json
    
    if not hasattr(result, 'os_fingerprints'):
        print("[!] No fingerprints collected")
        return
    
    data = {
        'fingerprints': result.os_fingerprints,
        'metadata': {
            'timestamp': time.time(),
            'total_hosts': len(result.os_fingerprints),
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"[✓] Saved {len(result.os_fingerprints)} fingerprints to {filename}")