"""
Defender AI Plugin
Monitor network traffic và detect port scanning attacks real-time
"""

import sys
import pickle
import json
import time
import threading
from pathlib import Path
from typing import Dict, List
from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime

try:
    import numpy as np
    import pandas as pd
    from scapy.all import *
except ImportError as e:
    print(f"[!] Missing packages for Defender AI: {e}")
    print("    Install: pip install numpy pandas scikit-learn scapy")
    sys.exit(1)

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType

conf.verb = 0


class FlowTracker:
    """Track network flows for analysis"""
    
    def __init__(self, timeout=10):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'dst_ports': [],
            'start_time': None,
            'last_seen': None
        })
        self.timeout = timeout
        self.lock = threading.Lock()
    
    def add_packet(self, packet_info: Dict) -> str:
        """Add packet to flow tracking"""
        flow_key = f"{packet_info['src_ip']}->{packet_info['dst_ip']}"
        
        with self.lock:
            flow = self.flows[flow_key]
            current_time = time.time()
            
            if flow['start_time'] is None:
                flow['start_time'] = current_time
            
            flow['packets'].append(packet_info)
            flow['dst_ports'].append(packet_info.get('dst_port', 0))
            flow['last_seen'] = current_time
        
        return flow_key
    
    def get_flow(self, flow_key: str) -> Dict:
        """Get flow info"""
        with self.lock:
            return dict(self.flows.get(flow_key, {}))
    
    def cleanup_old_flows(self):
        """Remove old flows"""
        current_time = time.time()
        with self.lock:
            to_remove = [
                key for key, flow in self.flows.items()
                if flow['last_seen'] and (current_time - flow['last_seen']) > self.timeout
            ]
            for key in to_remove:
                del self.flows[key]


class FeatureExtractor:
    """Extract ML features from network flow"""
    
    @staticmethod
    def extract(flow: Dict) -> Dict:
        """Extract features"""
        features = {}
        packets = flow.get('packets', [])
        n_packets = len(packets)
        
        if n_packets == 0:
            return features
        
        # Basic features
        features['total_fwd_packets'] = n_packets
        
        # Packet lengths
        lengths = [p.get('length', 0) for p in packets]
        features['total_length_fwd_packets'] = sum(lengths)
        features['fwd_packet_length_max'] = max(lengths) if lengths else 0
        features['fwd_packet_length_min'] = min(lengths) if lengths else 0
        features['fwd_packet_length_mean'] = np.mean(lengths) if lengths else 0
        features['fwd_packet_length_std'] = np.std(lengths) if lengths else 0
        
        # Time features
        timestamps = [p.get('timestamp', 0) for p in packets]
        if len(timestamps) > 1:
            diffs = np.diff(timestamps)
            features['flow_iat_mean'] = np.mean(diffs)
            features['flow_iat_std'] = np.std(diffs)
            features['flow_iat_max'] = np.max(diffs)
            features['flow_iat_min'] = np.min(diffs)
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
        
        # Entropy
        if dst_ports:
            from collections import Counter
            counts = Counter(dst_ports)
            total = len(dst_ports)
            entropy = 0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            features['dst_port_entropy'] = entropy
        else:
            features['dst_port_entropy'] = 0
        
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
        
        return features


class DefenderAIEngine:
    """Core Defender AI engine"""
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.selected_features = None
        
        self.load_models()
        
        self.flow_tracker = FlowTracker(timeout=10)
        self.blocked_ips = set()
        self.stats = {
            'packets': 0,
            'flows': 0,
            'attacks': 0,
            'blocked': 0
        }
        self.running = False
        self.alert_callbacks = []
    
    def load_models(self):
        """Load AI models"""
        try:
            model_path = self.model_dir / "defender_ai_model.pkl"
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            scaler_path = self.model_dir / "feature_scaler.pkl"
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            features_path = self.model_dir / "selected_features.json"
            with open(features_path, 'r') as f:
                self.selected_features = json.load(f)
            
            print(f"  [DEFENDER] ✅ Loaded AI models from {self.model_dir}")
            return True
            
        except Exception as e:
            print(f"  [DEFENDER] ⚠️  Could not load models: {e}")
            print(f"  [DEFENDER] Defender AI will not be available")
            return False
    
    def register_alert_callback(self, callback):
        """Register alert callback"""
        self.alert_callbacks.append(callback)
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            self.stats['packets'] += 1
            
            # Extract packet info
            packet_info = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'length': len(packet),
                'protocol': packet[IP].proto
            }
            
            # Check if IP is blocked
            if packet_info['src_ip'] in self.blocked_ips:
                return
            
            # TCP specific
            if packet.haslayer(TCP):
                packet_info.update({
                    'dst_port': packet[TCP].dport,
                    'syn': bool(packet[TCP].flags & 0x02),
                    'fin': bool(packet[TCP].flags & 0x01),
                    'rst': bool(packet[TCP].flags & 0x04),
                    'ack': bool(packet[TCP].flags & 0x10),
                })
            
            # Add to flow
            flow_key = self.flow_tracker.add_packet(packet_info)
            
            # Check if should analyze
            flow = self.flow_tracker.get_flow(flow_key)
            if self._should_analyze(flow):
                self._analyze_flow(flow_key, flow)
                
        except Exception as e:
            pass  # Silent fail to not interrupt packet capture
    
    def _should_analyze(self, flow: Dict) -> bool:
        """Decide when to analyze flow"""
        packet_count = len(flow.get('packets', []))
        
        # Analyze every 10 packets
        if packet_count % 10 == 0:
            return True
        
        # Or if many different ports
        unique_ports = len(set(flow.get('dst_ports', [])))
        if unique_ports >= 5:
            return True
        
        return False
    
    def _analyze_flow(self, flow_key: str, flow: Dict):
        """Analyze flow with AI"""
        try:
            self.stats['flows'] += 1
            
            # Extract features
            features = FeatureExtractor.extract(flow)
            if not features:
                return
            
            # Prepare for prediction
            df = pd.DataFrame([features])
            
            # Add missing features
            for feat in self.selected_features:
                if feat not in df.columns:
                    df[feat] = 0
            
            df = df[self.selected_features]
            X = self.scaler.transform(df)
            
            # Predict
            prediction = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            confidence = proba[prediction]
            
            # If attack detected
            if prediction == 1 and confidence >= 0.7:
                self._handle_threat(flow_key, flow, confidence, features)
                
        except Exception as e:
            pass  # Silent fail
    
    def _handle_threat(self, flow_key: str, flow: Dict, confidence: float, features: Dict):
        """Handle detected threat"""
        self.stats['attacks'] += 1
        
        packets = flow.get('packets', [])
        if not packets:
            return
        
        src_ip = packets[0]['src_ip']
        dst_ip = packets[0]['dst_ip']
        
        # Determine threat level
        if confidence >= 0.9:
            threat_level = "CRITICAL"
        elif confidence >= 0.7:
            threat_level = "HIGH"
        else:
            threat_level = "MEDIUM"
        
        # Alert
        alert_msg = (
            f"\n{Fore.RED}⚠️  ATTACK DETECTED!{Style.RESET_ALL}\n"
            f"   Source: {src_ip} → Target: {dst_ip}\n"
            f"   Threat: {threat_level} (confidence: {confidence:.2%})\n"
            f"   Ports: {len(set(flow.get('dst_ports', [])))} different ports\n"
            f"   Packets: {len(packets)}"
        )
        
        print(alert_msg)
        
        # Block IP if critical
        if confidence >= 0.85:
            self.blocked_ips.add(src_ip)
            self.stats['blocked'] += 1
            print(f"   {Fore.RED}🚫 IP BLOCKED: {src_ip}{Style.RESET_ALL}")
        
        # Call callbacks
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'threat_level': threat_level,
            'confidence': confidence,
            'ports': list(set(flow.get('dst_ports', []))),
            'packet_count': len(packets)
        }
        
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except:
                pass
    
    def start_monitoring(self, interface: str):
        """Start monitoring network"""
        self.running = True
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🛡️  DEFENDER AI MONITORING STARTED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"  Interface: {interface}")
        print(f"  Model: {'Loaded' if self.model else 'Not loaded'}")
        print(f"  Press Ctrl+C to stop\n")
        
        # Cleanup thread
        def cleanup():
            while self.running:
                self.flow_tracker.cleanup_old_flows()
                time.sleep(5)
        
        cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        cleanup_thread.start()
        
        # Start sniffing
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=False,
                filter="tcp"
            )
        except KeyboardInterrupt:
            self.running = False
            self._print_stats()
    
    def _print_stats(self):
        """Print statistics"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DEFENDER AI STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"  Packets Captured: {self.stats['packets']}")
        print(f"  Flows Analyzed: {self.stats['flows']}")
        print(f"  Attacks Detected: {self.stats['attacks']}")
        print(f"  IPs Blocked: {self.stats['blocked']}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


class DefenderAIPlugin(BasePlugin):
    """
    Defender AI Plugin
    Monitors network và detects attacks
    """
    
    def name(self) -> str:
        return "defender_ai"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Analyze  # Chạy sau scan
    
    def register_cli(self, parse: ArgumentParser):
        group = parse.add_argument_group('AI Defender Options')
        
        group.add_argument(
            '--ai-defend',
            action='store_true',
            help='Enable AI-powered attack detection (requires root/sudo)'
        )
        
        group.add_argument(
            '--ai-defend-interface',
            metavar='IFACE',
            default='eth0',
            help='Network interface to monitor (default: eth0)'
        )
        
        group.add_argument(
            '--ai-model-dir',
            metavar='DIR',
            default='./models',
            help='Directory containing defender AI models'
        )
    
    def run(self, context: ScanContext, args):
        """Run defender monitoring"""
        if not hasattr(args, 'ai_defend') or not args.ai_defend:
            return
        
        # Check root
        import os
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: Defender AI requires root privileges{Style.RESET_ALL}")
            print("    Run with: sudo python main.py --ai-defend ...")
            sys.exit(1)
        
        # Initialize engine
        model_dir = args.ai_model_dir if hasattr(args, 'ai_model_dir') else './models'
        interface = args.ai_defend_interface if hasattr(args, 'ai_defend_interface') else 'eth0'
        
        engine = DefenderAIEngine(model_dir=model_dir)
        
        # Register alert callback (optional)
        def save_alert(alert_data):
            # TODO: Save to file, send webhook, etc.
            pass
        
        engine.register_alert_callback(save_alert)
        
        # Start monitoring
        try:
            engine.start_monitoring(interface)
        except Exception as e:
            print(f"{Fore.RED}[!] Defender error: {e}{Style.RESET_ALL}")
            sys.exit(1)