"""
NetProbe Defender AI - Smart Network Defense System
Monitor network traffic và detect port scanning attacks real-time
Giống như Wireshark + AI-powered IDS/IPS
"""

import pickle
import json
import numpy as np
import pandas as pd
from scapy.all import *
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Mức độ threat"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DefenseMode(Enum):
    """Chế độ phòng thủ"""
    PASSIVE = "passive"      # Chỉ monitor, không block
    MODERATE = "moderate"    # Block critical threats only
    AGGRESSIVE = "aggressive"  # Block tất cả suspected threats


@dataclass
class ThreatAlert:
    """Thông tin về một threat được phát hiện"""
    timestamp: str
    source_ip: str
    destination_ip: str
    threat_level: ThreatLevel
    confidence: float
    attack_type: str
    ports_targeted: List[int]
    packet_count: int
    recommendation: str
    features: Dict


class FlowTracker:
    """
    Track network flows để phân tích
    Group packets thành flows dựa trên 5-tuple
    """
    
    def __init__(self, timeout: int = 10):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'dst_ports': [],
            'start_time': None,
            'last_seen': None,
            'packet_count': 0
        })
        self.timeout = timeout
        self.lock = threading.Lock()
    
    def add_packet(self, packet_info: Dict) -> str:
        """
        Thêm packet vào flow tracking
        
        Returns:
            flow_key
        """
        flow_key = f"{packet_info['src_ip']}->{packet_info['dst_ip']}"
        
        with self.lock:
            flow = self.flows[flow_key]
            
            current_time = time.time()
            
            if flow['start_time'] is None:
                flow['start_time'] = current_time
            
            flow['packets'].append(packet_info)
            flow['dst_ports'].append(packet_info.get('dst_port', 0))
            flow['last_seen'] = current_time
            flow['packet_count'] += 1
        
        return flow_key
    
    def get_flow(self, flow_key: str) -> Dict:
        """Lấy thông tin flow"""
        with self.lock:
            return self.flows.get(flow_key, {})
    
    def cleanup_old_flows(self):
        """Xóa flows cũ để tránh memory leak"""
        current_time = time.time()
        with self.lock:
            to_remove = []
            for key, flow in self.flows.items():
                if flow['last_seen'] and (current_time - flow['last_seen']) > self.timeout:
                    to_remove.append(key)
            
            for key in to_remove:
                del self.flows[key]
            
            if to_remove:
                logger.debug(f"Cleaned up {len(to_remove)} old flows")


class FeatureExtractor:
    """Extract ML features từ network flow"""
    
    @staticmethod
    def extract_from_flow(flow: Dict) -> Dict:
        """Extract features từ một flow"""
        features = {}
        
        packets = flow.get('packets', [])
        n_packets = len(packets)
        
        if n_packets == 0:
            return features
        
        # Basic counts
        features['total_fwd_packets'] = n_packets
        features['total_bwd_packets'] = 0  # TODO: Implement bidirectional tracking
        
        # Packet lengths
        lengths = [p.get('length', 0) for p in packets]
        features['total_length_fwd_packets'] = sum(lengths)
        features['fwd_packet_length_max'] = max(lengths) if lengths else 0
        features['fwd_packet_length_min'] = min(lengths) if lengths else 0
        features['fwd_packet_length_mean'] = np.mean(lengths) if lengths else 0
        features['fwd_packet_length_std'] = np.std(lengths) if lengths else 0
        
        # Time-based features
        timestamps = [p.get('timestamp', 0) for p in packets]
        if len(timestamps) > 1:
            time_diffs = np.diff(timestamps)
            features['flow_iat_mean'] = np.mean(time_diffs) if len(time_diffs) > 0 else 0
            features['flow_iat_std'] = np.std(time_diffs) if len(time_diffs) > 0 else 0
            features['flow_iat_max'] = np.max(time_diffs) if len(time_diffs) > 0 else 0
            features['flow_iat_min'] = np.min(time_diffs) if len(time_diffs) > 0 else 0
            features['flow_duration'] = timestamps[-1] - timestamps[0]
        else:
            features['flow_iat_mean'] = 0
            features['flow_iat_std'] = 0
            features['flow_iat_max'] = 0
            features['flow_iat_min'] = 0
            features['flow_duration'] = 0
        
        # Port scanning indicators
        dst_ports = flow.get('dst_ports', [])
        features['unique_dst_ports'] = len(set(dst_ports))
        features['dst_port_entropy'] = FeatureExtractor._calculate_entropy(dst_ports)
        
        # Packet rate
        if features['flow_duration'] > 0:
            features['fwd_packets_s'] = n_packets / features['flow_duration']
        else:
            features['fwd_packets_s'] = 0
        
        # TCP flags
        features['syn_flag_count'] = sum(1 for p in packets if p.get('syn', False))
        features['fin_flag_count'] = sum(1 for p in packets if p.get('fin', False))
        features['rst_flag_count'] = sum(1 for p in packets if p.get('rst', False))
        features['ack_flag_count'] = sum(1 for p in packets if p.get('ack', False))
        features['psh_flag_count'] = sum(1 for p in packets if p.get('psh', False))
        features['urg_flag_count'] = sum(1 for p in packets if p.get('urg', False))
        
        return features
    
    @staticmethod
    def _calculate_entropy(data: List) -> float:
        """Tính entropy"""
        if not data:
            return 0.0
        
        from collections import Counter
        counts = Counter(data)
        total = len(data)
        
        entropy = 0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy


class DefenderAI:
    """
    AI-powered Network Defense System
    Giống như Wireshark + IDS/IPS
    """
    
    def __init__(self, model_dir: str = "./models", mode: DefenseMode = DefenseMode.MODERATE):
        self.model_dir = model_dir
        self.mode = mode
        
        # Load AI model
        self.model = None
        self.scaler = None
        self.selected_features = None
        self.load_models()
        
        # Flow tracking
        self.flow_tracker = FlowTracker(timeout=10)
        
        # Blocked IPs
        self.blocked_ips = set()
        self.block_duration = {}  # IP -> unblock_time
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'flows_analyzed': 0,
            'attacks_detected': 0,
            'ips_blocked': 0,
            'start_time': datetime.now()
        }
        
        # Callbacks
        self.alert_callbacks = []
        
        # Start cleanup thread
        self.running = False
        
    def load_models(self):
        """Load AI models"""
        try:
            model_path = Path(self.model_dir) / "defender_ai_model.pkl"
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            scaler_path = Path(self.model_dir) / "feature_scaler.pkl"
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            features_path = Path(self.model_dir) / "selected_features.json"
            with open(features_path, 'r') as f:
                self.selected_features = json.load(f)
            
            logger.info("✅ Defender AI models loaded successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
            return False
    
    def register_alert_callback(self, callback: Callable[[ThreatAlert], None]):
        """Register một callback function cho alerts"""
        self.alert_callbacks.append(callback)
    
    def _packet_handler(self, packet):
        """Handler cho mỗi packet được capture"""
        try:
            # Chỉ process IP packets
            if not packet.haslayer(IP):
                return
            
            self.stats['packets_captured'] += 1
            
            # Extract packet info
            packet_info = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'length': len(packet),
                'protocol': packet[IP].proto
            }
            
            # Check nếu IP đã bị block
            if packet_info['src_ip'] in self.blocked_ips:
                logger.debug(f"🚫 Dropped packet from blocked IP: {packet_info['src_ip']}")
                return
            
            # TCP specific
            if packet.haslayer(TCP):
                packet_info.update({
                    'dst_port': packet[TCP].dport,
                    'src_port': packet[TCP].sport,
                    'syn': bool(packet[TCP].flags & 0x02),
                    'fin': bool(packet[TCP].flags & 0x01),
                    'rst': bool(packet[TCP].flags & 0x04),
                    'ack': bool(packet[TCP].flags & 0x10),
                    'psh': bool(packet[TCP].flags & 0x08),
                    'urg': bool(packet[TCP].flags & 0x20),
                })
            
            # UDP specific
            elif packet.haslayer(UDP):
                packet_info.update({
                    'dst_port': packet[UDP].dport,
                    'src_port': packet[UDP].sport,
                })
            
            # Add to flow tracker
            flow_key = self.flow_tracker.add_packet(packet_info)
            
            # Check if should analyze this flow
            flow = self.flow_tracker.get_flow(flow_key)
            if self._should_analyze_flow(flow):
                self._analyze_flow(flow_key, flow)
        
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
    
    def _should_analyze_flow(self, flow: Dict) -> bool:
        """Quyết định khi nào analyze flow"""
        packet_count = flow.get('packet_count', 0)
        
        # Analyze sau mỗi 10 packets
        if packet_count % 10 == 0:
            return True
        
        # Hoặc nếu có nhiều ports khác nhau (possible scan)
        unique_ports = len(set(flow.get('dst_ports', [])))
        if unique_ports >= 5:
            return True
        
        return False
    
    def _analyze_flow(self, flow_key: str, flow: Dict):
        """Analyze flow với AI model"""
        try:
            self.stats['flows_analyzed'] += 1
            
            # Extract features
            features = FeatureExtractor.extract_from_flow(flow)
            
            if not features:
                return
            
            # Predict
            df = pd.DataFrame([features])
            
            # Ensure all required features exist
            for feat in self.selected_features:
                if feat not in df.columns:
                    df[feat] = 0
            
            df = df[self.selected_features]
            X_scaled = self.scaler.transform(df)
            
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            confidence = probabilities[prediction]
            
            # Nếu detect attack
            if prediction == 1:
                self._handle_threat(flow_key, flow, confidence, features)
        
        except Exception as e:
            logger.error(f"Error analyzing flow: {e}")
    
    def _handle_threat(self, flow_key: str, flow: Dict, confidence: float, features: Dict):
        """Xử lý khi phát hiện threat"""
        self.stats['attacks_detected'] += 1
        
        # Determine threat level
        if confidence >= 0.9:
            threat_level = ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            threat_level = ThreatLevel.HIGH
        elif confidence >= 0.5:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        # Get flow info
        packets = flow.get('packets', [])
        if not packets:
            return
        
        src_ip = packets[0].get('src_ip', 'unknown')
        dst_ip = packets[0].get('dst_ip', 'unknown')
        
        # Create alert
        alert = ThreatAlert(
            timestamp=datetime.now().isoformat(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            threat_level=threat_level,
            confidence=confidence,
            attack_type="Port Scan",
            ports_targeted=list(set(flow.get('dst_ports', []))),
            packet_count=len(packets),
            recommendation=self._get_recommendation(threat_level, confidence),
            features=features
        )
        
        # Log alert
        logger.warning(f"\n⚠️  THREAT DETECTED!")
        logger.warning(f"   Source: {src_ip} → Target: {dst_ip}")
        logger.warning(f"   Threat Level: {threat_level.value}")
        logger.warning(f"   Confidence: {confidence:.2%}")
        logger.warning(f"   Ports Targeted: {len(alert.ports_targeted)}")
        
        # Block IP based on mode and threat level
        if self._should_block(threat_level, confidence):
            self._block_ip(src_ip, duration=3600)  # Block 1 hour
            logger.warning(f"   🚫 IP BLOCKED: {src_ip}")
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def _should_block(self, threat_level: ThreatLevel, confidence: float) -> bool:
        """Quyết định có nên block IP không"""
        if self.mode == DefenseMode.PASSIVE:
            return False
        elif self.mode == DefenseMode.MODERATE:
            return threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] and confidence >= 0.8
        elif self.mode == DefenseMode.AGGRESSIVE:
            return threat_level != ThreatLevel.SAFE and confidence >= 0.6
        return False
    
    def _block_ip(self, ip: str, duration: int):
        """Block một IP"""
        self.blocked_ips.add(ip)
        self.block_duration[ip] = time.time() + duration
        self.stats['ips_blocked'] += 1
        
        # TODO: Implement actual firewall rules
        # os.system(f"iptables -A INPUT -s {ip} -j DROP")
    
    def _get_recommendation(self, threat_level: ThreatLevel, confidence: float) -> str:
        """Đưa ra khuyến nghị"""
        if threat_level == ThreatLevel.CRITICAL:
            return "BLOCK immediately - Critical threat detected"
        elif threat_level == ThreatLevel.HIGH:
            return "ALERT security team - High probability attack"
        elif threat_level == ThreatLevel.MEDIUM:
            return "MONITOR closely - Suspicious activity detected"
        else:
            return "LOG for analysis - Low confidence detection"
    
    def start_monitoring(self, interface: str = "eth0", filter_rule: str = "tcp"):
        """
        Bắt đầu monitor network traffic
        
        Args:
            interface: Network interface (e.g., "eth0", "wlan0")
            filter_rule: BPF filter (e.g., "tcp", "tcp port 80")
        """
        self.running = True
        
        logger.info(f"🛡️  Starting Defender AI on interface: {interface}")
        logger.info(f"   Defense Mode: {self.mode.value}")
        logger.info(f"   Filter: {filter_rule}")
        logger.info("-" * 60)
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup_thread.start()
        
        # Start packet capture
        try:
            sniff(
                iface=interface,
                filter=filter_rule,
                prn=self._packet_handler,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("\n⏹️  Stopping monitoring...")
            self.running = False
            self._print_final_stats()
    
    def _cleanup_loop(self):
        """Background thread để cleanup"""
        while self.running:
            # Cleanup old flows
            self.flow_tracker.cleanup_old_flows()
            
            # Unblock expired IPs
            current_time = time.time()
            to_unblock = []
            for ip, unblock_time in self.block_duration.items():
                if current_time >= unblock_time:
                    to_unblock.append(ip)
            
            for ip in to_unblock:
                self.blocked_ips.remove(ip)
                del self.block_duration[ip]
                logger.info(f"✅ Unblocked IP: {ip}")
            
            time.sleep(5)
    
    def _print_final_stats(self):
        """Print statistics"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        logger.info("\n" + "="*60)
        logger.info("📊 Defender AI Statistics")
        logger.info("="*60)
        logger.info(f"Uptime: {uptime:.0f} seconds")
        logger.info(f"Packets Captured: {self.stats['packets_captured']}")
        logger.info(f"Flows Analyzed: {self.stats['flows_analyzed']}")
        logger.info(f"Attacks Detected: {self.stats['attacks_detected']}")
        logger.info(f"IPs Blocked: {self.stats['ips_blocked']}")
        logger.info(f"Currently Blocked IPs: {len(self.blocked_ips)}")
        logger.info("="*60)


# ==================== CLI Usage ====================

if __name__ == "__main__":
    import argparse
    from pathlib import Path
    
    parser = argparse.ArgumentParser(description="NetProbe Defender AI - Smart Network Defense")
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('-f', '--filter', default='tcp', help='BPF filter')
    parser.add_argument('-m', '--mode', choices=['passive', 'moderate', 'aggressive'],
                       default='moderate', help='Defense mode')
    parser.add_argument('--model-dir', default='./models', help='Directory containing AI models')
    
    args = parser.parse_args()
    
    # Convert mode
    mode_map = {
        'passive': DefenseMode.PASSIVE,
        'moderate': DefenseMode.MODERATE,
        'aggressive': DefenseMode.AGGRESSIVE
    }
    
    print(f"""
    ╔════════════════════════════════════════════╗
    ║   NetProbe Defender AI - Network Defense   ║
    ╚════════════════════════════════════════════╝
    
    Interface: {args.interface}
    Mode: {args.mode.upper()}
    Filter: {args.filter}
    
    ⚠️  Note: Requires root privileges (sudo)
    """)
    
    # Initialize defender
    defender = DefenderAI(
        model_dir=args.model_dir,
        mode=mode_map[args.mode]
    )
    
    # Optional: Register custom alert handler
    def custom_alert_handler(alert: ThreatAlert):
        # TODO: Send email, SMS, webhook, etc.
        print(f"\n📧 Alert sent: {alert.attack_type} from {alert.source_ip}")
    
    defender.register_alert_callback(custom_alert_handler)
    
    # Start monitoring
    defender.start_monitoring(
        interface=args.interface,
        filter_rule=args.filter
    )