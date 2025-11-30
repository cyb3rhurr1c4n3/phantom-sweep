from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.analyzer_base import AnalyzerBase
import warnings
import os
import logging
from phantom_sweep.module.analyzer.os.os_detection import OSDetectionScanner

# Suppress all sklearn warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore')

# Suppress parallel output
os.environ['JOBLIB_TEMP_FOLDER'] = '/tmp'
logging.getLogger('sklearn').setLevel(logging.ERROR)

class AIOSFingerprinter(AnalyzerBase):
    """AI-powered OS fingerprinting using Random Forest"""
    @property
    def name(self) -> str:
        return "ai"
    
    @property
    def description(self) -> str:
        return "AI-powered OS detection using Random Forest"
    
    def __init__(self):
        self.predictor = None
        self.os_scanner = None
        self._load_predictor()
    
    def _load_predictor(self):
        """Load OS predictor and scanner"""
        try:
            from phantom_sweep.module.analyzer.os.os_predictor import OSPredictor
            
            self.os_scanner = OSDetectionScanner()
            self.predictor = OSPredictor()
            
            if not self.predictor.is_ready():
                print("[!] AI OS Detection: Model files not found")
                print("    Please place model files in phantom_sweep/models/")
                self.predictor = None
        except Exception as e:
            print(f"[!] Error loading OS predictor: {e}")
            self.predictor = None
    
    def analyze(self, context: ScanContext, result: ScanResult):
        """Perform AI-based OS fingerprinting"""
        if not self.predictor or not self.os_scanner:
            if context.verbose:
                print("[!] AI OS fingerprinting not available")
            return
        
        if context.verbose:
            print("[*] Running AI OS fingerprinting...")
        
        # Step 1: Collect fingerprints
        self.os_scanner.scan(context, result)
        # Step 2: Predict OS
        if not hasattr(result, 'os_fingerprints') or not result.os_fingerprints:
            if context.verbose:
                print("  [!] No fingerprints collected")
            return
        
        # Predict for each host
        for host, fingerprint in result.os_fingerprints.items():
            try:
                os_name, confidence, details = self.predictor.predict(fingerprint)
                
                # Update result
                if host in result.hosts:
                    result.hosts[host].os = os_name
                    result.hosts[host].os_accuracy = int(confidence)
                
                if context.verbose:
                    print(f"  [{host}] → {os_name} ({confidence:.1f}% confidence)")
            
            except Exception as e:
                if context.debug:
                    print(f"  [!] Prediction error for {host}: {e}")

class NormalOSFingerprinter(AnalyzerBase):
    """Normal OS Fingerprint"""
    @property
    def name(self) -> str:
        return "normal"
    
    @property
    def description(self) -> str:
        return "TTL/Window size-based OS detection"
    
    def __init__(self):
        self.os_scanner = None
        self._load_analyzer()
    
    def _load_analyzer(self):
        """Load OS predictor and scanner"""
        try:
            
            self.os_scanner = OSDetectionScanner()
        except Exception as e:
            print(f"[!] Error loading OS predictor: {e}")
    
    def analyze(self, context: ScanContext, result: ScanResult):
        """Perform AI-based OS fingerprinting"""
        if not self.os_scanner:
            if context.verbose:
                print("[!] Normal OS fingerprinting not available")
            return
        
        if context.verbose:
            print("[*] Running normal OS fingerprinting...")
        
        # Step 1: Collect fingerprints
        self.os_scanner.scan(context, result)
        # Step 2: Predict OS
        if not hasattr(result, 'os_fingerprints') or not result.os_fingerprints:
            if context.verbose:
                print("  [!] No fingerprints collected")
            return
        
        for host, fingerprint in result.os_fingerprints.items():
            try:
                # print(fingerprint)
                result.hosts[host].os = fingerprint["os_hint_from_banner"]
                result.hosts[host].os_version = str(fingerprint["possible_os_version"])
                result.hosts[host].os_accuracy = 100

                if context.verbose:
                    print(f"  [{host}] → {fingerprint["os_hint_from_banner"]} ({100:.1f}% confidence)")
            
            except Exception as e:
                if context.debug:
                    print(f"  [!] Scan error for {host}: {e}")
