"""
Database-driven Service Detection
Uses service_probe.db (Nmap-style) for accurate service identification
"""
import socket
import os
from typing import Dict, Optional, Tuple
from phantom_sweep.module._base.analyzer_base import AnalyzerBase
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module.analyzer.service.service_probe_parser import (
    get_service_probe_parser,
    ServiceProbeParser
)


# Fallback port-to-service mapping (used when probe matching fails)
FALLBACK_SERVICE_MAP = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
    6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
    9200: 'elasticsearch', 27017: 'mongodb',
}


class DatabaseServiceDetection(AnalyzerBase):
    """Service detection using service_probe.db database"""
    
    def __init__(self, probe_db_path: Optional[str] = None):
        """
        Initialize service detection
        
        Args:
            probe_db_path: Path to service_probe.db file
                          If None, tries to find it in default locations
        """
        self.parser: ServiceProbeParser = get_service_probe_parser()
        self.probe_db_loaded = False
        
        # Try to load probe database
        if probe_db_path:
            self._load_probe_db(probe_db_path)
        else:
            self._load_default_probe_db()
    
    @property
    def name(self) -> str:
        return "normal"
    
    @property
    def description(self) -> str:
        return "Database-driven service detection (Nmap-style)"
    
    def _load_probe_db(self, filepath: str) -> bool:
        """Load service probe database from file"""
        try:
            if os.path.exists(filepath):
                self.parser.parse_file(filepath)
                self.probe_db_loaded = len(self.parser.probes) > 0
                return self.probe_db_loaded
        except Exception as e:
            print(f"[!] Error loading probe database: {e}")
        return False
    
    def _load_default_probe_db(self) -> bool:
        """Try to load probe database from default locations"""
        default_paths = [
            'service_probe.db',
            'data/service_probe.db',
            os.path.join(os.path.dirname(__file__), 'service_probe.db'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'service_probe.db'),
        ]
        
        for path in default_paths:
            if self._load_probe_db(path):
                return True
        
        return False
    
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """Perform service detection on open ports"""
        if context.verbose:
            mode_str = "database-driven" if self.probe_db_loaded else "fallback port-based"
            print(f"[*] Starting service detection ({mode_str})...")
            if self.probe_db_loaded:
                print(f"[*] Loaded {len(self.parser.probes)} service probes from database")
        
        detected_count = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            # Detect services on TCP ports
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    service, version, confidence = self._detect_service_tcp(
                        host, port, context.performance.timeout, context.debug
                    )
                    
                    if service:
                        port_info.service = service
                        if version:
                            port_info.version = version
                        port_info.extra['confidence'] = confidence
                        detected_count += 1
                        
                        if context.debug:
                            print(
                                f"[DEBUG] {host}:{port}/tcp -> {service} "
                                f"{version or ''} (confidence: {confidence}%)"
                            )
        
        if context.verbose:
            print(f"[*] Service detection completed: {detected_count} services identified")
    
    def _detect_service_tcp(
        self, host: str, port: int, timeout: float, debug: bool = False
    ) -> Tuple[Optional[str], Optional[str], int]:
        """
        Detect service on TCP port using probe database
        
        Returns:
            Tuple of (service_name, version, confidence_score)
        """
        if not self.probe_db_loaded:
            # Fallback to simple port-based detection
            service = FALLBACK_SERVICE_MAP.get(port, 'unknown')
            return (service, None, 50)
        
        # Get applicable probes for this port
        probes = self.parser.get_probes_for_port(port, protocol="TCP")
        
        if not probes:
            # No probes found, use fallback
            service = FALLBACK_SERVICE_MAP.get(port, 'unknown')
            return (service, None, 50)
        
        # Try probes in order of rarity
        for probe in probes[:5]:  # Limit to first 5 probes to avoid timeout
            try:
                # Send probe and get response
                response = self._send_probe(host, port, probe.probe_string, timeout)
                
                if response:
                    # Try to match response
                    match_result = self.parser.match_response(response, [probe])
                    
                    if match_result:
                        service_name, version_info, confidence = match_result
                        
                        # Build version string from version_info
                        version = self._build_version_string(version_info)
                        
                        if debug:
                            print(f"[DEBUG] Matched with probe: {probe.probe_name}")
                        
                        return (service_name, version, confidence)
                
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Probe {probe.probe_name} failed: {e}")
                continue
        
        # No match found, try NULL probe (passive banner grab)
        try:
            response = self._send_probe(host, port, b'', timeout)
            if response:
                # Try to match against all probes
                match_result = self.parser.match_response(response, probes)
                if match_result:
                    service_name, version_info, confidence = match_result
                    version = self._build_version_string(version_info)
                    return (service_name, version, confidence)
        except:
            pass
        
        # Complete fallback
        service = FALLBACK_SERVICE_MAP.get(port, 'unknown')
        return (service, None, 30)
    
    def _send_probe(
        self, host: str, port: int, probe_data: bytes, timeout: float
    ) -> Optional[bytes]:
        """
        Send probe to service and return response
        
        Args:
            host: Target host
            port: Target port
            probe_data: Probe data to send (empty for NULL probe)
            timeout: Socket timeout
            
        Returns:
            Response bytes or None
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect
            sock.connect((host, port))
            
            # Send probe if not NULL probe
            if probe_data:
                sock.sendall(probe_data)
            
            # Receive response (up to 10KB to catch verbose banners)
            response = sock.recv(10240)
            
            sock.close()
            
            return response if response else None
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None
    
    def _build_version_string(self, version_info: Dict[str, str]) -> Optional[str]:
        """
        Build version string from version_info dictionary
        
        Args:
            version_info: Dictionary with keys like 'product', 'version', 'info', etc.
            
        Returns:
            Formatted version string or None
        """
        parts = []
        
        # Product name
        if 'product' in version_info:
            parts.append(version_info['product'])
        
        # Version number
        if 'version' in version_info:
            parts.append(version_info['version'])
        
        # Additional info
        if 'info' in version_info:
            parts.append(f"({version_info['info']})")
        
        return ' '.join(parts) if parts else None

