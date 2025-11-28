"""
Service Detection - AI Mode
Enhanced service detection with multi-probe correlation and ML-inspired scoring
"""
import socket
import time
from typing import Dict, Optional, Tuple
from phantom_sweep.module._base.analyzer_base import AnalyzerBase
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module.analyzer.service.service_probe_parser import get_service_probe_parser


class AIServiceDetection(AnalyzerBase):
    """AI-enhanced service detection with multi-probe correlation"""
    
    def __init__(self):
        """Initialize AI service detection"""
        import os
        self.parser = get_service_probe_parser()
        self.probe_db_loaded = False
        self.probe_db_path = None
        
        # Load probe database
        search_paths = [
            'service_probes.db',
            'data/service_probes.db',
            os.path.join(os.path.dirname(__file__), 'service_probes.db'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'service_probes.db'),
            '/usr/share/nmap/nmap-service-probes',
        ]
        
        for path in search_paths:
            try:
                if os.path.exists(path) and os.path.isfile(path):
                    self.parser.parse_file(path)
                    if len(self.parser.probes) > 0:
                        self.probe_db_loaded = True
                        self.probe_db_path = path
                        break
            except:
                continue
    
    @property
    def name(self) -> str:
        return "ai"
    
    @property
    def description(self) -> str:
        return "AI-powered service detection with multi-probe analysis"
    
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """Perform AI-enhanced service detection"""
        if not self.probe_db_loaded:
            if context.verbose:
                print("[!] Probe database not loaded - using fallback detection")
            self._fallback_detection(context, result)
            return
        
        if context.verbose:
            print(f"[*] Starting AI-powered service detection...")
            print(f"[*] Using {len(self.parser.probes)} probes with multi-probe correlation")
        
        detected_count = 0
        total_ports = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    total_ports += 1
                    service, version, confidence = self._ai_detect_service(
                        host, port, context.performance.timeout, context.debug
                    )
                    
                    if service and confidence >= 50:
                        port_info.service = service
                        if version:
                            port_info.version = version
                        port_info.extra['confidence'] = confidence
                        port_info.extra['detection_method'] = 'ai'
                        detected_count += 1
                        
                        if context.debug:
                            version_str = f" {version}" if version else ""
                            print(f"[DEBUG] {host}:{port}/tcp -> {service}{version_str} (AI confidence: {confidence}%)")
        
        if context.verbose:
            print(f"[*] AI service detection completed: {detected_count}/{total_ports} services identified")
    
    def _ai_detect_service(
        self, host: str, port: int, timeout: float, debug: bool = False
    ) -> Tuple[Optional[str], Optional[str], int]:
        """AI-enhanced service detection with multiple signals"""
        signals = {}
        
        # Signal 1: Port-based heuristic (20 points)
        port_service = self._simple_port_detection(port)
        if port_service != 'unknown':
            signals['port_heuristic'] = {'service': port_service, 'version': None, 'weight': 20}
        
        # Signal 2: Primary probe detection (50 points)
        primary_service, primary_version = self._detect_service(host, port, timeout, False)
        if primary_service and primary_service != 'unknown':
            signals['primary_probe'] = {'service': primary_service, 'version': primary_version, 'weight': 50}
        
        # Signal 3: Multi-probe correlation (30 points)
        correlation_result = self._multi_probe_correlation(host, port, timeout, debug)
        if correlation_result:
            signals['correlation'] = correlation_result
        
        # Signal 4: Behavioral analysis (bonus +15)
        behavioral_bonus = self._behavioral_analysis(host, port, timeout)
        
        # Aggregate signals
        service, version, confidence = self._aggregate_signals(signals, behavioral_bonus)
        return (service, version, confidence)
    
    def _detect_service(
        self, host: str, port: int, timeout: float, debug: bool
    ) -> Tuple[Optional[str], Optional[str]]:
        """Basic service detection using probes"""
        probes = self.parser.get_probes_for_port(port, protocol="TCP")
        if not probes:
            return (self._simple_port_detection(port), None)
        
        # Try NULL probe first
        null_probe = next((p for p in probes if p.probe_name == "NULL"), None)
        if null_probe:
            result = self._try_probe(host, port, null_probe, timeout, debug)
            if result:
                return result
        
        # Try other probes
        for probe in probes[:10]:
            if probe.probe_name == "NULL":
                continue
            result = self._try_probe(host, port, probe, timeout, debug)
            if result:
                return result
        
        return (self._simple_port_detection(port), None)
    
    def _try_probe(
        self, host: str, port: int, probe, timeout: float, debug: bool
    ) -> Optional[Tuple[str, Optional[str]]]:
        """Try a single probe"""
        try:
            response = self._send_probe(host, port, probe.probe_string, timeout)
            if not response:
                return None
            
            match_result = self.parser.match_response(response, [probe])
            if match_result:
                service_name, version_info, confidence = match_result
                version = self._build_version_string(version_info)
                return (service_name, version)
        except:
            pass
        return None
    
    def _send_probe(self, host: str, port: int, probe_data: bytes, timeout: float) -> Optional[bytes]:
        """Send probe and receive response"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            if probe_data:
                sock.sendall(probe_data)
            response = sock.recv(10240)
            return response if response else None
        except:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _build_version_string(self, version_info: dict) -> Optional[str]:
        """Build version string"""
        parts = []
        if 'product' in version_info:
            parts.append(version_info['product'])
        if 'version' in version_info:
            parts.append(version_info['version'])
        if 'info' in version_info and version_info['info']:
            parts.append(f"({version_info['info']})")
        return ' '.join(parts) if parts else None
    
    def _multi_probe_correlation(
        self, host: str, port: int, timeout: float, debug: bool
    ) -> Optional[Dict]:
        """Try multiple probes and correlate results"""
        probes = self.parser.get_probes_for_port(port, protocol="TCP")
        if len(probes) < 2:
            return None
        
        probe_results = []
        for probe in probes[:5]:
            try:
                result = self._try_probe(host, port, probe, timeout * 0.6, False)
                if result:
                    probe_results.append(result)
            except:
                continue
        
        if not probe_results:
            return None
        
        # Count service occurrences
        service_counts = {}
        version_map = {}
        for service, version in probe_results:
            service_counts[service] = service_counts.get(service, 0) + 1
            if version and service not in version_map:
                version_map[service] = version
        
        # Most common service
        most_common = max(service_counts, key=service_counts.get)
        agreement_ratio = service_counts[most_common] / len(probe_results)
        weight = int(30 * agreement_ratio)
        
        if debug:
            print(f"[DEBUG] Multi-probe correlation: {agreement_ratio:.1%} agreement on {most_common}")
        
        return {'service': most_common, 'version': version_map.get(most_common), 'weight': weight}
    
    def _behavioral_analysis(self, host: str, port: int, timeout: float) -> int:
        """Analyze service behavior for additional hints"""
        bonus = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            start = time.time()
            sock.connect((host, port))
            connection_time = time.time() - start
            
            if connection_time < 0.05:
                bonus += 3
            
            sock.settimeout(0.2)
            try:
                data = sock.recv(1024)
                if data:
                    bonus += 5
                    if len(data) > 100:
                        bonus += 2
            except socket.timeout:
                pass
            
            sock.close()
        except:
            pass
        
        return min(bonus, 15)
    
    def _aggregate_signals(self, signals: Dict, behavioral_bonus: int) -> Tuple[Optional[str], Optional[str], int]:
        """Aggregate detection signals using weighted voting"""
        if not signals:
            return (None, None, 0)
        
        service_scores = {}
        version_map = {}
        
        for signal_name, signal_data in signals.items():
            service = signal_data['service']
            version = signal_data['version']
            weight = signal_data['weight']
            
            service_scores[service] = service_scores.get(service, 0) + weight
            if version and service not in version_map:
                version_map[service] = version
        
        best_service = max(service_scores, key=service_scores.get)
        base_confidence = service_scores[best_service]
        total_confidence = min(base_confidence + behavioral_bonus, 100)
        version = version_map.get(best_service)
        
        return (best_service, version, total_confidence)
    
    def _simple_port_detection(self, port: int) -> str:
        """Simple port-based service detection"""
        port_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
            9200: 'elasticsearch', 27017: 'mongodb',
        }
        return port_map.get(port, 'unknown')
    
    def _fallback_detection(self, context: ScanContext, result: ScanResult) -> None:
        """Fallback detection when probe database is not available"""
        detected_count = 0
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    service = self._simple_port_detection(port)
                    port_info.service = service
                    detected_count += 1
        if context.verbose:
            print(f"[*] Fallback detection completed: {detected_count} services identified")