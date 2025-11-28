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
        self._load_ai_model()
    
    @property
    def name(self) -> str:
        return "ai"
    
    @property
    def description(self) -> str:
        return "AI-powered service detection using ML model"
    
    def _load_ai_model(self) -> None:
        """Load trained AI model"""
        model_paths = [
            'models/service_detection_rf_model.pkl',
            'data/models/service_detection_rf_model.pkl',
            os.path.join(os.path.dirname(__file__), 'models', 'service_detection_rf_model.pkl'),
        ]
        
        vectorizer_paths = [
            'models/service_detection_vectorizer.pkl',
            'data/models/service_detection_vectorizer.pkl',
            os.path.join(os.path.dirname(__file__), 'models', 'service_detection_vectorizer.pkl'),
        ]
        
        # Load model
        for path in model_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        self.model = pickle.load(f)
                    break
            except:
                continue
        
        # Load vectorizer
        for path in vectorizer_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        self.vectorizer = pickle.load(f)
                    break
            except:
                continue
        
        if self.model and self.vectorizer:
            self.model_loaded = True
    
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """Perform AI service detection"""
        if not self.model_loaded:
            if context.verbose:
                print("[!] AI model not loaded - using fallback detection")
            self._fallback_detection(context, result)
            return
        
        if context.verbose:
            print(f"[*] Starting AI-powered service detection...")
        
        detected_count = 0
        total_ports = 0
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    total_ports += 1
                    service, confidence = self._ai_detect_service(
                        host, port, context.performance.timeout, context.debug
                    )
                    
                    if service and confidence >= 50:
                        port_info.service = service
                        port_info.extra['confidence'] = confidence
                        port_info.extra['detection_method'] = 'ai'
                        detected_count += 1
                        
                        if context.debug:
                            print(f"[DEBUG] {host}:{port}/tcp -> {service} (AI confidence: {confidence:.2f}%)")
        
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
                return (None, 0.0)
            
            # Preprocess banner
            banner_clean = banner.decode('utf-8', errors='ignore').lower()[:500]
            
            # Vectorize
            banner_vec = self.vectorizer.transform([banner_clean])
            
            # Predict
            service = self.model.predict(banner_vec)[0]
            probabilities = self.model.predict_proba(banner_vec)[0]
            confidence = max(probabilities) * 100
            
            if debug:
                top_3 = sorted(zip(self.model.classes_, probabilities), 
                              key=lambda x: x[1], reverse=True)[:3]
                print(f"[DEBUG] AI Top 3 predictions:")
                for svc, prob in top_3:
                    print(f"  - {svc}: {prob*100:.2f}%")
            
            return (service, confidence)
            
        except Exception as e:
            if debug:
                print(f"[DEBUG] AI prediction failed: {e}")
            return (None, 0.0)
    
    def _grab_banner(self, host: str, port: int, timeout: float) -> Optional[bytes]:
        """Grab banner from service"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.settimeout(0.5)
            banner = sock.recv(4096)
            return banner
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
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
        }
        
        for host, host_info in result.hosts.items():
            if host_info.state != "up":
                continue
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    port_info.service = port_map.get(port, 'unknown')