import joblib
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Optional
import warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', message='.*InconsistentVersionWarning.*')
warnings.filterwarnings('ignore', message='.*X does not have valid feature names.*')

# Tắt sklearn verbose output
import os
os.environ['PYTHONWARNINGS'] = 'ignore'


class OSPredictor:
    """Predict OS from fingerprints using ML model"""
    
    def __init__(self, model_dir: Optional[str] = None):
        """
        Initialize predictor with trained model
        
        Args:
            model_dir: Directory containing model files. 
                      If None, looks in ./models or ../models
        """
        self.model = None
        self.target_encoder = None
        self.feature_encoders = None
        self.model_info = None
        
        # Find model directory
        if model_dir:
            self.model_dir = Path(model_dir)
        else:
            # Try multiple locations relative to project root
            current_file = Path(__file__).resolve()  # /path/to/phantom_sweep/module/analyzer/os_predictor.py
            analyzer_dir = current_file.parent       # /path/to/phantom_sweep/module/analyzer/
            module_dir = analyzer_dir.parent         # /path/to/phantom_sweep/module/
            phantom_sweep_dir = module_dir.parent    # /path/to/phantom_sweep/
            project_root = phantom_sweep_dir.parent  # /path/to/project_root/
            
            possible_dirs = [
                phantom_sweep_dir / 'models',        # phantom_sweep/models/
                project_root / 'phantom_sweep' / 'models',  # project_root/phantom_sweep/models/
                Path('phantom_sweep/models'),        # Relative path
                Path('models'),                      # Current dir
            ]
            
            for dir_path in possible_dirs:
                if dir_path.exists() and (dir_path / 'os_detection_model.pkl').exists():
                    self.model_dir = dir_path
                    break
            else:
                self.model_dir = None
        
        # Load model
        self._load_model()
    
    def _load_model(self):
        """Load trained model and encoders"""
        if not self.model_dir:
            print("[!] Model directory not found")
            print("    Please place model files in 'models/' directory")
            return
        
        try:
            import logging
            logging.getLogger('sklearn').setLevel(logging.ERROR)

            # Load model
            model_path = self.model_dir / 'os_detection_model.pkl'
            self.model = joblib.load(model_path)
            if hasattr(self.model, 'verbose'):
                self.model.verbose = 0
            
            # Also set for all estimators in the forest
            if hasattr(self.model, 'estimators_'):
                for estimator in self.model.estimators_:
                    if hasattr(estimator, 'verbose'):
                        estimator.verbose = 0
            # Load encoders
            self.target_encoder = joblib.load(self.model_dir / 'target_encoder.pkl')
            self.feature_encoders = joblib.load(self.model_dir / 'feature_encoders.pkl')
            
            # Load model info (optional)
            import json
            info_path = self.model_dir / 'model_info.json'
            if info_path.exists():
                with open(info_path, 'r') as f:
                    self.model_info = json.load(f)
        
        except Exception as e:
            print(f"[!] Failed to load model: {e}")
            self.model = None
    
    def is_ready(self) -> bool:
        """Check if model is loaded and ready"""
        return self.model is not None
    
    def predict(self, fingerprint: Dict) -> Tuple[str, float, Dict]:
        """
        Predict OS from fingerprint
        
        Args:
            fingerprint: Dictionary with keys:
                - ttl: TTL value
                - window_size: TCP window size
                - df_flag: Don't Fragment flag (0/1)
                - ip_id_sequence: IP ID sequence type
                - icmp_response: ICMP response (0/1)
        
        Returns:
            Tuple of (os_name, confidence, details)
            - os_name: Predicted OS (e.g., "Linux")
            - confidence: Confidence percentage (0-100)
            - details: Dict with top predictions and features used
        """
        if not self.is_ready():
            return "Unknown", 0.0, {"error": "Model not loaded"}
        
        try:
            # Normalize features
            ttl_group = self._normalize_ttl(fingerprint.get('ttl'))
            window_group = self._group_window_size(fingerprint.get('window_size'))
            
            # Prepare features
            features = {
                'ttl_group': ttl_group,
                'window_group': window_group,
                'df_flag': fingerprint.get('df_flag', -1),
                'ip_id_sequence': fingerprint.get('ip_id_sequence', 'unknown'),
                'icmp_response': fingerprint.get('icmp_response', -1)
            }
            
            # Encode features
            feature_columns = ['ttl_group', 'window_group', 'df_flag', 
                              'ip_id_sequence', 'icmp_response']
            encoded_features = []
            
            for col in feature_columns:
                if col in self.feature_encoders:
                    try:
                        val = self.feature_encoders[col].transform([str(features[col])])[0]
                    except ValueError:
                        # Unknown category
                        val = -1
                else:
                    val = features[col]
                encoded_features.append(val)
            
            # Predict
            X = np.array([encoded_features])
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Decode prediction
            os_name = self.target_encoder.inverse_transform([prediction])[0]
            confidence = probabilities[prediction] * 100
            
            # Get top 3 predictions
            top_3_idx = probabilities.argsort()[-3:][::-1]
            top_3 = [
                {
                    'os': self.target_encoder.inverse_transform([i])[0],
                    'confidence': probabilities[i] * 100
                }
                for i in top_3_idx
            ]
            
            # Details
            details = {
                'top_predictions': top_3,
                'features_used': features,
                'confidence_score': confidence
            }
            
            return os_name, confidence, details
        
        except Exception as e:
            return "Unknown", 0.0, {"error": str(e)}
    
    def predict_from_scan_result(self, host: str, scan_result) -> Tuple[str, float]:
        """
        Predict OS from ScanResult object
        
        Args:
            host: IP address
            scan_result: ScanResult object with os_fingerprints
        
        Returns:
            Tuple of (os_name, confidence)
        """
        if not hasattr(scan_result, 'os_fingerprints'):
            return "Unknown", 0.0
        
        if host not in scan_result.os_fingerprints:
            return "Unknown", 0.0
        
        fingerprint = scan_result.os_fingerprints[host]
        os_name, confidence, _ = self.predict(fingerprint)
        
        return os_name, confidence
    
    def _normalize_ttl(self, ttl) -> str:
        """Normalize TTL value to groups"""
        if ttl is None:
            return 'unknown'
        try:
            ttl = int(ttl)
            if ttl <= 64:
                return '64'
            elif ttl <= 128:
                return '128'
            else:
                return '255'
        except:
            return 'unknown'
    
    def _group_window_size(self, window) -> str:
        """Group window size"""
        if window is None:
            return 'unknown'
        try:
            window = int(window)
            if window < 8192:
                return 'small'
            elif window < 65535:
                return 'medium'
            else:
                return 'large'
        except:
            return 'unknown'


# Convenience function for quick prediction
def predict_os(fingerprint: Dict, model_dir: Optional[str] = None) -> Tuple[str, float]:
    """
    Quick OS prediction from fingerprint
    
    Args:
        fingerprint: Fingerprint dictionary
        model_dir: Optional model directory path
    
    Returns:
        Tuple of (os_name, confidence)
    
    Example:
        >>> fp = {'ttl': 64, 'window_size': 5840, 'df_flag': 1}
        >>> os_name, conf = predict_os(fp)
        >>> print(f"{os_name} ({conf:.1f}%)")
        Linux (94.2%)
    """
    predictor = OSPredictor(model_dir)
    os_name, confidence, _ = predictor.predict(fingerprint)
    return os_name, confidence


# For use as scanner module/plugin
class OSPredictorModule:
    """
    Scanner module for OS prediction
    Compatible with phantom_sweep plugin system
    """
    
    def __init__(self):
        self.predictor = OSPredictor()
    
    @property
    def name(self) -> str:
        return "os_predict"
    
    @property
    def type(self) -> str:
        return "os_prediction"
    
    @property
    def description(self) -> str:
        return "Predict OS using AI (Random Forest)"
    
    def requires_root(self) -> bool:
        return False
    
    def scan(self, context, result):
        """
        Perform OS prediction on all fingerprinted hosts
        
        Args:
            context: ScanContext object
            result: ScanResult object with os_fingerprints
        """
        if not self.predictor.is_ready():
            print("[!] OS Predictor: Model not loaded")
            return
        
        if not hasattr(result, 'os_fingerprints'):
            print("[!] OS Predictor: No fingerprints found")
            print("    Run 'os_detect' scanner first")
            return
        
        if not result.os_fingerprints:
            print("[!] OS Predictor: No fingerprints to predict")
            return
        
        if context.verbose:
            print(f"[*] Predicting OS for {len(result.os_fingerprints)} hosts...")
        
        # Initialize predictions dict in result
        if not hasattr(result, 'os_predictions'):
            result.os_predictions = {}
        
        # Predict for each host
        for host, fingerprint in result.os_fingerprints.items():
            try:
                os_name, confidence, details = self.predictor.predict(fingerprint)
                
                result.os_predictions[host] = {
                    'os': os_name,
                    'confidence': confidence,
                    'details': details
                }
                
                if context.verbose:
                    print(f"  [{host}] → {os_name} ({confidence:.1f}% confidence)")
            
            except Exception as e:
                if context.debug:
                    print(f"  [!] Prediction error for {host}: {e}")


if __name__ == '__main__':
    # Test predictor
    print("Testing OS Predictor...")
    print()
    
    predictor = OSPredictor()
    