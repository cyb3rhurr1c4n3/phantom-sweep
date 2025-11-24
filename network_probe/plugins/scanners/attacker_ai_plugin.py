"""
AI-Powered Stealth Scanner Plugin
Sử dụng DQN để tạo evasive port scans
"""

import sys
import socket
from typing import Dict, List
from argparse import ArgumentParser
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    import torch
    import torch.nn as nn
    import numpy as np
    from scapy.all import *
except ImportError as e:
    print(f"[!] Missing required packages for AI Attack: {e}")
    print("    Install: pip install torch scapy")
    sys.exit(1)

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin, BaseScanner
from network_probe.plugins.plugin_types import PluginType

conf.verb = 0


class DQNNetwork(nn.Module):
    """Deep Q-Network for attack strategy selection"""
    
    def __init__(self, state_dim=10, action_dims=[6, 10, 2, 5]):
        super(DQNNetwork, self).__init__()
        self.action_dims = action_dims
        
        # Shared network
        self.shared = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 128),
            nn.ReLU()
        )
        
        # Separate heads for each action
        self.heads = nn.ModuleList([
            nn.Linear(128, dim) for dim in action_dims
        ])
    
    def forward(self, x):
        shared = self.shared(x)
        return [head(shared) for head in self.heads]


class AttackerAIScanner(BaseScanner):
    """
    AI-powered stealth scanner
    Thay thế cho TCP/UDP scanner thông thường
    """
    
    def __init__(self, model_path=None, stealth_level='medium'):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize DQN
        self.model = DQNNetwork().to(self.device)
        
        # Load model nếu có
        if model_path:
            try:
                self.model.load_state_dict(
                    torch.load(model_path, map_location=self.device)
                )
                self.model.eval()
                print(f"  [AI] ✅ Loaded Attacker AI model from {model_path}")
            except Exception as e:
                print(f"  [AI] ⚠️  Could not load model: {e}")
                print(f"  [AI] Using random strategy")
        
        self.stealth_level = stealth_level
        self.stealth_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'extreme': 4
        }
        
    def _parse_ports(self, context: ScanContext) -> List[int]:
        """Parse ports từ context"""
        ports = set()
        
        if context.scan_all_ports:
            return list(range(1, 65536))
        
        if context.fast_scan:
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                   993, 995, 3306, 3389, 5900, 8080]
        
        if context.ports:
            parts = context.ports.split(',')
            for part in parts:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if 0 < start <= end <= 65535:
                        ports.update(range(start, end + 1))
                else:
                    port = int(part)
                    if 0 < port <= 65535:
                        ports.add(port)
            return sorted(list(ports))
        
        # Default ports
        return [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
    
    def _get_state(self, progress: Dict) -> np.ndarray:
        """Create state vector for DQN"""
        state = np.zeros(10)
        
        state[0] = progress.get('scanned_ratio', 0)
        state[1] = progress.get('detected', 0)
        state[2] = progress.get('response_rate', 0)
        state[3] = progress.get('avg_response_time', 0)
        state[4] = self.stealth_map.get(self.stealth_level, 2) / 4
        state[5] = progress.get('total_ports', 1000) / 10000
        state[6] = progress.get('open_ports_ratio', 0)
        state[7] = progress.get('success_rate', 0)
        state[8] = np.random.random()
        state[9] = (progress.get('scan_time', 0) % 10) / 10
        
        return state
    
    def _choose_strategy(self, progress: Dict) -> Dict:
        """Use DQN to choose scan strategy"""
        state = self._get_state(progress)
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            q_values = self.model(state_tensor)
            actions = [torch.argmax(q).item() for q in q_values]
        
        # Map actions to strategy
        scan_types = ['SYN', 'ACK', 'FIN', 'NULL', 'XMAS', 'UDP']
        
        strategy = {
            'scan_type': scan_types[actions[0] % len(scan_types)],
            'delay': actions[1] * 0.1,  # 0-1 second
            'randomize': bool(actions[2]),
            'fragment': bool(actions[3] > 2)
        }
        
        # Apply stealth multiplier
        if self.stealth_level == 'extreme':
            strategy['delay'] *= 5
        elif self.stealth_level == 'high':
            strategy['delay'] *= 2
        
        return strategy
    
    def _scan_port_stealth(self, target: str, port: int, strategy: Dict, 
                          timeout: float) -> Dict:
        """
        Scan một port với strategy từ AI
        """
        scan_type = strategy['scan_type']
        
        try:
            if scan_type == 'SYN':
                # SYN scan
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=timeout, verbose=0)
                
                if response is None:
                    return {'port': port, 'state': 'filtered'}
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        # Send RST
                        rst = IP(dst=target)/TCP(dport=port, flags="R")
                        send(rst, verbose=0)
                        return {'port': port, 'state': 'open'}
                    elif response[TCP].flags == 0x14:  # RST-ACK
                        return {'port': port, 'state': 'closed'}
            
            elif scan_type == 'FIN':
                # FIN scan (stealth)
                packet = IP(dst=target)/TCP(dport=port, flags="F")
                response = sr1(packet, timeout=timeout, verbose=0)
                
                if response is None:
                    return {'port': port, 'state': 'open|filtered'}
                elif response.haslayer(TCP) and response[TCP].flags == 0x14:
                    return {'port': port, 'state': 'closed'}
            
            elif scan_type == 'NULL':
                # NULL scan
                packet = IP(dst=target)/TCP(dport=port, flags="")
                response = sr1(packet, timeout=timeout, verbose=0)
                
                if response is None:
                    return {'port': port, 'state': 'open|filtered'}
                elif response.haslayer(TCP) and response[TCP].flags == 0x14:
                    return {'port': port, 'state': 'closed'}
            
            elif scan_type == 'XMAS':
                # XMAS scan
                packet = IP(dst=target)/TCP(dport=port, flags="FPU")
                response = sr1(packet, timeout=timeout, verbose=0)
                
                if response is None:
                    return {'port': port, 'state': 'open|filtered'}
                elif response.haslayer(TCP) and response[TCP].flags == 0x14:
                    return {'port': port, 'state': 'closed'}
            
            return {'port': port, 'state': 'unknown'}
            
        except Exception as e:
            return {'port': port, 'state': 'error', 'error': str(e)}
    
    def scan(self, target: str, context: ScanContext) -> Dict[str, any]:
        """
        Main scan function - AI-powered
        """
        ports = self._parse_ports(context)
        open_ports = {}
        
        try:
            ip_target = socket.gethostbyname(target)
        except socket.gaierror:
            return {"error": f"Cannot resolve: {target}"}
        
        if context.debug:
            print(f"  [AI-ATTACK] 🤖 Scanning {len(ports)} ports on {ip_target}")
            print(f"  [AI-ATTACK] 🥷 Stealth Level: {self.stealth_level.upper()}")
        
        import time
        start_time = time.time()
        
        # Randomize port order nếu strategy yêu cầu
        progress = {
            'scanned_ratio': 0,
            'detected': 0,
            'response_rate': 0,
            'total_ports': len(ports),
            'scan_time': 0
        }
        
        strategy = self._choose_strategy(progress)
        
        if strategy['randomize']:
            import random
            random.shuffle(ports)
        
        if context.debug:
            print(f"  [AI-ATTACK] 📊 Strategy: {strategy['scan_type']}, "
                  f"Delay: {strategy['delay']:.2f}s")
        
        # Scan ports
        for i, port in enumerate(ports):
            # Update progress
            progress['scanned_ratio'] = i / len(ports)
            progress['scan_time'] = time.time() - start_time
            
            # Get new strategy periodically
            if i % 10 == 0 and i > 0:
                strategy = self._choose_strategy(progress)
            
            # Apply delay
            if strategy['delay'] > 0:
                time.sleep(strategy['delay'])
            
            # Scan port
            result = self._scan_port_stealth(
                ip_target, port, strategy, context.timeout
            )
            
            if result['state'] in ['open', 'open|filtered']:
                open_ports[port] = {
                    'state': result['state'],
                    'service': 'unknown'
                }
            
            # Progress indicator
            if context.verbose and (i + 1) % 50 == 0:
                print(f"  [AI-ATTACK] Progress: {i+1}/{len(ports)} ports")
        
        duration = time.time() - start_time
        
        if context.debug:
            print(f"  [AI-ATTACK] ✅ Scan complete in {duration:.2f}s")
            print(f"  [AI-ATTACK] 🎯 Found {len(open_ports)} open/filtered ports")
        
        return {
            "ports": open_ports,
            "scan_duration": duration,
            "stealth_level": self.stealth_level,
            "ai_powered": True
        }


class AttackerAIPlugin(BasePlugin):
    """
    Plugin để enable AI-powered stealth scanning
    """
    
    def name(self) -> str:
        return "attacker_ai"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan
    
    def register_cli(self, parse: ArgumentParser):
        group = parse.add_argument_group('AI Attacker Options')
        
        group.add_argument(
            '--ai-attack',
            action='store_true',
            help='Enable AI-powered stealth scanning (requires root/sudo)'
        )
        
        group.add_argument(
            '--ai-stealth',
            choices=['low', 'medium', 'high', 'extreme'],
            default='medium',
            help='AI stealth level (default: medium)'
        )
        
        group.add_argument(
            '--ai-model',
            metavar='PATH',
            help='Path to trained Attacker AI model (.pth file)'
        )
    
    def run(self, context: ScanContext, args):
        """Run AI-powered scan"""
        if not hasattr(args, 'ai_attack') or not args.ai_attack:
            return
        
        # Check root privileges
        # import os
        # if os.geteuid() != 0:
        #     print(f"{Fore.RED}[!] Error: AI Attack mode requires root privileges{Style.RESET_ALL}")
        #     print("    Run with: sudo python main.py --ai-attack ...")
        #     sys.exit(1)
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🤖 AI ATTACKER MODE ACTIVATED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # Initialize AI scanner
        try:
            scanner = AttackerAIScanner(
                model_path=args.ai_model if hasattr(args, 'ai_model') else None,
                stealth_level=args.ai_stealth if hasattr(args, 'ai_stealth') else 'medium'
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize AI Attacker: {e}{Style.RESET_ALL}")
            sys.exit(1)
        
        scan_results = {}
        lock = threading.Lock()
        
        def scan_target(target):
            try:
                result = scanner.scan(target, context)
                with lock:
                    if "error" in result:
                        print(f"[!] Error scanning {target}: {result['error']}")
                    scan_results[target] = result
            except Exception as e:
                print(f"{Fore.RED}[!] Critical error scanning {target}: {e}{Style.RESET_ALL}")
        
        # Scan targets (sequential for stealth, or use limited threads)
        max_workers = 1 if args.ai_stealth in ['high', 'extreme'] else min(3, context.threads)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(scan_target, context.targets)
        
        context.set_data("scan_results", scan_results)
        
        print(f"\n{Fore.GREEN}[*] AI Attack Scan completed{Style.RESET_ALL}")
        
        # Summary
        total_open = sum(len(r.get('ports', {})) for r in scan_results.values())
        print(f"    Total open/filtered ports found: {total_open}")