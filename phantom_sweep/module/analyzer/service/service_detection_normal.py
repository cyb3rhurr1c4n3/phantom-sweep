"""
Service Detection - Normal Mode
Uses service_probes.db (Nmap-style database) for accurate service identification
"""
import socket
import os
from typing import Optional, Tuple
from phantom_sweep.module._base.analyzer_base import AnalyzerBase
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module.analyzer.service.service_probe_parser import (
    get_service_probe_parser,
    ServiceProbeParser
)


class NormalServiceDetection(AnalyzerBase):
    """Service detection using Nmap-style service probes database"""
    
    def __init__(self):
        """Initialize service detection with probe database"""
        self.parser: ServiceProbeParser = get_service_probe_parser()
        self.probe_db_loaded = False
        self.probe_db_path = None
        self._load_probe_database()
    
    @property
    def name(self) -> str:
        return "normal"
    
    @property
    def description(self) -> str:
        return "Banner-based service detection using probe database"
    
    def _load_probe_database(self) -> None:
        """Load service probe database from various locations"""
        search_paths = [
            'service_probes.db',
            'data/service_probes.db',
            os.path.join(os.path.dirname(__file__), 'service_probes.db'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'service_probes.db'),
            os.path.join(os.path.dirname(__file__), 'service', 'service_probes.db')
        ]
        
        for path in search_paths:
            try:
                if os.path.exists(path) and os.path.isfile(path):
                    self.parser.parse_file(path)
                    if len(self.parser.probes) > 0:
                        self.probe_db_loaded = True
                        self.probe_db_path = path
                        return
            except Exception:
                continue
    
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """Perform service detection on open ports"""
        if not self.probe_db_loaded:
            if context.verbose:
                print("[!] Service probe database not found - using fallback detection")
            self._fallback_detection(context, result)
            return
        
        if context.verbose:
            print(f"[*] Starting service detection...")
            print(f"[*] Loaded {len(self.parser.probes)} service probes from: {self.probe_db_path}")
        
        detected_count = 0
        total_ports = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    total_ports += 1
                    service, version, banner = self._detect_service(
                        host, port, context.performance.timeout, context.debug
                    )
                    
                    if service:
                        port_info.service = service
                        if version:
                            port_info.version = version
                        if banner:
                            port_info.banner = banner
                        detected_count += 1
                        
                        if context.debug:
                            version_str = f" {version}" if version else ""
                            print(f"[DEBUG] {host}:{port}/tcp -> {service}{version_str}")
        
        if context.verbose:
            print(f"[*] Service detection completed: {detected_count}/{total_ports} services identified")
    
    def _detect_service(
        self, host: str, port: int, timeout: float, debug: bool = False
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Detect service on a specific port using probe database
        
        Returns:
            Tuple of (service_name, version_string, banner)
        """
        probes = self.parser.get_probes_for_port(port, protocol="TCP")
        
        if not probes:
            if debug:
                print(f"[DEBUG] No probes found for port {port}, using fallback")
            service, _ = self._simple_port_detection(port)
            return (service, None, None)
        
        # CRITICAL: Try NULL probe first (passive banner grab)
        # This is the most important probe - gets immediate banner
        null_probe = next((p for p in probes if p.probe_name == "NULL"), None)
        if null_probe:
            result = self._try_probe(host, port, null_probe, timeout, debug)
            if result:
                return result
        
        # Try other probes by rarity (lower = more common)
        # Limit to 15 probes to avoid excessive timeout
        for probe in probes[:15]:
            if probe.probe_name == "NULL":
                continue  # Already tried
            
            result = self._try_probe(host, port, probe, timeout, debug)
            if result:
                return result
        
        # No match - fallback to port-based detection
        if debug:
            print(f"[DEBUG] No probe matched for port {port}, using fallback")
        service, _ = self._simple_port_detection(port)
        return (service, None, None)
    
    def _try_probe(
        self, host: str, port: int, probe, timeout: float, debug: bool
    ) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
        """
        Try a single probe and match response
        
        Returns:
            Tuple of (service, version, banner) or None
        """
        try:
            # Send probe and get response
            response = self._send_probe(host, port, probe.probe_string, timeout)
            
            if not response:
                return None
            
            # Store raw banner
            banner = response.decode('utf-8', errors='ignore')[:200]
            
            # Try to match response against probe patterns
            match_result = self.parser.match_response(response, [probe])
            
            if match_result:
                service_name, version_info, confidence = match_result
                version = self._build_version_string(version_info)
                
                if debug:
                    print(f"[DEBUG] ✓ Matched probe '{probe.probe_name}' → {service_name} (confidence: {confidence}%)")
                
                return (service_name, version, banner)
            
            # Even if pattern didn't match, if we got a response from NULL probe,
            # try generic pattern matching on the banner
            if probe.probe_name == "NULL" and response:
                service = self._generic_banner_match(response, port)
                if service:
                    if debug:
                        print(f"[DEBUG] ✓ Generic banner match → {service}")
                    return (service, None, banner)
        
        except Exception as e:
            if debug:
                print(f"[DEBUG] ✗ Probe '{probe.probe_name}' failed: {e}")
        
        return None
    
    def _send_probe(
        self, host: str, port: int, probe_data: bytes, timeout: float
    ) -> Optional[bytes]:
        """
        Send probe to target and receive response
        
        CRITICAL: This must establish FULL TCP connection, not just SYN
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Establish full TCP connection
            sock.connect((host, port))
            
            # Send probe data if not NULL probe
            if probe_data:
                sock.sendall(probe_data)
            
            # Wait briefly for response
            sock.settimeout(0.5)  # Give service time to respond
            
            # Receive response (up to 10KB for verbose banners)
            response = b''
            try:
                while len(response) < 10240:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass  # Normal - service sent what it had
            
            return response if response else None
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except OSError:
            return None
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _generic_banner_match(self, banner: bytes, port: int) -> Optional[str]:
        """
        Generic pattern matching on banner when specific probe doesn't match
        
        This catches common services by their banner patterns
        """
        try:
            banner_str = banner.decode('utf-8', errors='ignore').lower()
            
            # SSH detection
            if banner_str.startswith('ssh-'):
                return 'ssh'
            
            # HTTP detection
            if 'http/' in banner_str or '<html' in banner_str:
                return 'http'
            
            # FTP detection
            if banner_str.startswith('220') and 'ftp' in banner_str:
                return 'ftp'
            
            # SMTP detection
            if banner_str.startswith('220') and ('smtp' in banner_str or 'mail' in banner_str):
                return 'smtp'
            
            # Telnet detection
            if b'\xff\xfb' in banner or b'\xff\xfd' in banner:  # Telnet IAC commands
                return 'telnet'
            
            # MySQL detection
            if b'\x00\x00\x00' in banner[:10] and (b'mysql' in banner.lower() or b'\x0a' in banner[:10]):
                return 'mysql'
            
            # PostgreSQL detection
            if b'postgres' in banner.lower() or (banner_str.startswith('e') and 'fatal' in banner_str):
                return 'postgresql'
            
        except:
            pass
        
        # Fallback to port-based detection
        return None
    
    def _build_version_string(self, version_info: dict) -> Optional[str]:
        """
        Build version string from version info dict
        
        Format: product version (info)
        Example: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
        """
        parts = []
        
        # Product name
        if 'product' in version_info:
            parts.append(version_info['product'])
        
        # Version number
        if 'version' in version_info:
            parts.append(version_info['version'])
        
        # Additional info
        if 'info' in version_info and version_info['info']:
            parts.append(version_info['info'])
        
        # OS info
        if 'os' in version_info and version_info['os']:
            parts.append(f"({version_info['os']})")
        
        return ' '.join(parts) if parts else None
    
    def _simple_port_detection(self, port: int) -> Tuple[str, None]:
        """Simple port-based service detection (fallback)"""
        port_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
            9200: 'elasticsearch', 27017: 'mongodb', 31337: 'Elite',
        }
        return (port_map.get(port, 'unknown'), None)
    
    def _fallback_detection(self, context: ScanContext, result: ScanResult) -> None:
        """Fallback detection when probe database is not available"""
        detected_count = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    service, _ = self._simple_port_detection(port)
                    port_info.service = service
                    detected_count += 1
        
        if context.verbose:
            print(f"[*] Fallback detection completed: {detected_count} services identified")