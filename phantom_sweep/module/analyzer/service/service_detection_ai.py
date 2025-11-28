"""
Service Detection - AI Mode
AI-powered service detection using trained ML model
"""
import socket
import pickle
import os
from typing import Optional, Tuple
from phantom_sweep.module._base.analyzer_base import AnalyzerBase
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult


class AIServiceDetection(AnalyzerBase):
    """AI-powered service detection using trained ML model"""
    
    def __init__(self):
        """Initialize AI service detection"""
        self.model = None
        self.vectorizer = None
        self.model_loaded = False
    
    @property
    def name(self) -> str:
        return "ai"
    
    @property
    def description(self) -> str:
        return "AI-powered service detection using ML model"
    
    def _load_ai_model(self) -> None:
        """Load trained AI model"""
        # Possible model locations
        base_paths = [
            # Current directory
            os.getcwd(),
            # Project root (where phantom.py is)
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            # Module directory
            os.path.dirname(__file__),
        ]
        
        model_subdirs = [
            'models',
            'phantom_sweep/models',
            'data/models',
            'phantom_sweep/data/models',
        ]
        # Build all possible paths
        model_paths = []
        vectorizer_paths = []
        
        for base in base_paths:
            for subdir in model_subdirs:
                model_dir = os.path.join(base, subdir)
                model_paths.append(os.path.join(model_dir, 'service_detection_rf_model.pkl'))
                model_paths.append(os.path.join(model_dir, 'service_detection_gb_model.pkl'))
                vectorizer_paths.append(os.path.join(model_dir, 'service_detection_vectorizer.pkl'))
        
        # Try to load model
        for path in model_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        self.model = pickle.load(f)
                    self.model_path = path
                    print(f"[DEBUG] ✅ AI Model loaded from: {path}") # Bổ sung thông báo thành công
                    break
            except Exception as e:
                # Bổ sung in lỗi cụ thể để gỡ lỗi
                print(f"[ERROR] ❌ Failed to load model from {path}. Error: {e}")
                continue
        
        # Try to load vectorizer
        for path in vectorizer_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        self.vectorizer = pickle.load(f)
                    self.vectorizer_path = path
                    break
            except Exception as e:
                continue
        
        if self.model and self.vectorizer:
            self.model_loaded = True
    
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        self._load_ai_model()
        """Perform AI service detection"""
        if not self.model_loaded:
            if context.verbose:
                print("[!] AI model not loaded - searching in:")
                # Show searched paths for debugging
                base_dir = os.getcwd()
                for subdir in ['models', 'phantom_sweep/models', 'data/models']:
                    path = os.path.join(base_dir, subdir)
                    exists = "✓" if os.path.exists(path) else "✗"
                    print(f"    {exists} {path}")
                print("[!] Using fallback port-based detection")
            self._fallback_detection(context, result)
            return
        
        if context.verbose:
            print(f"[*] Starting AI-powered service detection...")
            print(f"[*] Model loaded from: {self.model_path}")
        
        detected_count = 0
        total_ports = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    total_ports += 1
                    
                    if context.debug:
                        print(f"[DEBUG] AI detecting service on {host}:{port}...")
                    
                    service, confidence = self._ai_detect_service(
                        host, port, context.performance.timeout, context.debug
                    )
                    
                    if service and confidence >= 50:
                        port_info.service = service
                        port_info.extra['confidence'] = confidence
                        port_info.extra['detection_method'] = 'ai'
                        detected_count += 1
                        
                        if context.debug:
                            print(f"[DEBUG] ✓ {host}:{port}/tcp -> {service} (AI confidence: {confidence:.2f}%)")
        
        if context.verbose:
            print(f"[*] AI service detection completed: {detected_count}/{total_ports} services identified")
    
    def _ai_detect_service(
        self, host: str, port: int, timeout: float, debug: bool
    ) -> Tuple[Optional[str], float]:
        """AI-powered service detection"""
        try:
            # Grab banner
            banner = self._grab_banner(host, port, timeout)
            if not banner:
                if debug:
                    print(f"[DEBUG]   No banner received")
                return (None, 0.0)
            
            if debug:
                banner_preview = banner[:100].decode('utf-8', errors='ignore').replace('\r', '\\r').replace('\n', '\\n')
                print(f"[DEBUG]   Banner: {banner_preview}...")
            
            # Preprocess banner
            banner_clean = banner.decode('utf-8', errors='ignore').lower()[:500]
            
            # Vectorize
            banner_vec = self.vectorizer.transform([banner_clean])
            
            # Predict
            service = self.model.predict(banner_vec)[0]
            probabilities = self.model.predict_proba(banner_vec)[0]
            confidence = max(probabilities) * 100
            
            if debug:
                # Show top 3 predictions
                top_3_indices = probabilities.argsort()[-3:][::-1]
                print(f"[DEBUG]   AI Top 3 predictions:")
                for idx in top_3_indices:
                    svc = self.model.classes_[idx]
                    prob = probabilities[idx] * 100
                    print(f"[DEBUG]     {svc}: {prob:.2f}%")
            
            return (service, confidence)
            
        except Exception as e:
            if debug:
                print(f"[DEBUG]   AI prediction error: {e}")
            return (None, 0.0)
    
    def _grab_banner(self, host: str, port: int, timeout: float) -> Optional[bytes]:
        """Grab banner from service"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Wait for banner
            sock.settimeout(1.0)
            banner = b''
            try:
                while len(banner) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                    if len(chunk) < 1024:
                        sock.settimeout(0.2)
            except socket.timeout:
                pass
            
            return banner if banner else None
        except:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _fallback_detection(self, context: ScanContext, result: ScanResult) -> None:
        """Fallback to port-based detection"""
        port_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
            9200: 'elasticsearch', 9929: 'nping-echo', 27017: 'mongodb',
            31337: 'Elite',
        }
        
        detected_count = 0
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    port_info.service = port_map.get(port, 'unknown')
                    detected_count += 1
        
        if context.verbose:
            print(f"[*] Fallback detection completed: {detected_count} services identified")