"""
AI Training Mode Plugin
Cho phép Attacker AI và Defender AI tự đấu nhau và học
"""

import sys
import time
import json
import threading
from typing import Dict, List
from argparse import ArgumentParser
from pathlib import Path
from datetime import datetime

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import numpy as np
except ImportError:
    print("[!] Missing PyTorch for training mode")
    sys.exit(1)

from colorama import Fore, Style
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class TrainingEnvironment:
    """
    Environment cho AI training
    Attacker AI cố gắng scan mà không bị phát hiện
    Defender AI cố gắng phát hiện scans
    """
    
    def __init__(self, attacker_model, defender_model):
        self.attacker = attacker_model
        self.defender = defender_model
        
        self.history = []
        self.stats = {
            'total_rounds': 0,
            'attacker_wins': 0,  # Không bị phát hiện
            'defender_wins': 0,  # Phát hiện được
            'attacker_rewards': [],
            'defender_rewards': []
        }
    
    def run_round(self, round_num: int) -> Dict:
        """
        Chạy một round training
        
        Returns:
            Round results
        """
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎮 TRAINING ROUND {round_num}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # 1. Attacker generates scan strategy
        attacker_state = self._get_attacker_state()
        attacker_action = self.attacker.choose_action(attacker_state)
        
        print(f"  [ATTACKER] 🔴 Strategy: {self._format_action(attacker_action)}")
        
        # 2. Simulate scan với strategy đó
        scan_result = self._simulate_scan(attacker_action)
        
        print(f"  [SCAN] 📡 Executed {scan_result['packets_sent']} packets, "
              f"{scan_result['ports_scanned']} ports")
        
        # 3. Defender analyzes traffic
        defender_state = self._extract_defender_features(scan_result)
        defender_prediction = self.defender.predict(defender_state)
        
        is_detected = defender_prediction == 1  # 1 = attack
        confidence = defender_prediction
        
        if is_detected:
            print(f"  [DEFENDER] 🛡️  DETECTED (confidence: {confidence:.2%})")
            self.stats['defender_wins'] += 1
        else:
            print(f"  [DEFENDER] 🛡️  NOT DETECTED")
            self.stats['attacker_wins'] += 1
        
        # 4. Calculate rewards
        attacker_reward = self._calculate_attacker_reward(is_detected, scan_result)
        defender_reward = self._calculate_defender_reward(is_detected, scan_result)
        
        print(f"  [REWARDS] 🎯 Attacker: {attacker_reward:+.2f}, "
              f"Defender: {defender_reward:+.2f}")
        
        # 5. Store results
        round_result = {
            'round': round_num,
            'attacker_action': attacker_action,
            'scan_result': scan_result,
            'detected': is_detected,
            'confidence': confidence,
            'attacker_reward': attacker_reward,
            'defender_reward': defender_reward,
            'timestamp': datetime.now().isoformat()
        }
        
        self.history.append(round_result)
        self.stats['total_rounds'] += 1
        self.stats['attacker_rewards'].append(attacker_reward)
        self.stats['defender_rewards'].append(defender_reward)
        
        return round_result
    
    def _get_attacker_state(self) -> np.ndarray:
        """Get current state for attacker"""
        state = np.zeros(10)
        
        # Historical performance
        if len(self.history) > 0:
            recent = self.history[-10:]
            state[0] = sum(1 for r in recent if not r['detected']) / len(recent)  # Success rate
            state[1] = np.mean([r['attacker_reward'] for r in recent])
            state[2] = len([r for r in recent if r['detected']]) / len(recent)  # Detection rate
        
        # Current round info
        state[3] = self.stats['total_rounds'] / 1000  # Normalized
        state[4] = np.random.random()  # Randomness
        
        return state
    
    def _simulate_scan(self, action: Dict) -> Dict:
        """
        Simulate một scan với strategy được chọn
        
        Returns:
            Scan characteristics
        """
        scan_type = action.get('scan_type', 'SYN')
        delay = action.get('delay', 0.1)
        num_ports = action.get('num_ports', 50)
        randomize = action.get('randomize', False)
        
        # Simulate packet characteristics
        packets_sent = num_ports
        
        # Timing characteristics
        if delay > 0.5:
            timing_pattern = 'slow'
            avg_iat = delay
        elif delay > 0.1:
            timing_pattern = 'medium'
            avg_iat = delay
        else:
            timing_pattern = 'fast'
            avg_iat = delay
        
        # Port distribution
        if randomize:
            port_entropy = np.random.uniform(3.0, 4.0)  # High entropy
        else:
            port_entropy = np.random.uniform(0.5, 2.0)  # Low entropy
        
        result = {
            'packets_sent': packets_sent,
            'ports_scanned': num_ports,
            'scan_type': scan_type,
            'timing_pattern': timing_pattern,
            'avg_iat': avg_iat,
            'port_entropy': port_entropy,
            'delay': delay,
            'randomize': randomize,
            'syn_count': packets_sent if scan_type == 'SYN' else 0,
            'fin_count': packets_sent if scan_type == 'FIN' else 0
        }
        
        return result
    
    def _extract_defender_features(self, scan_result: Dict) -> np.ndarray:
        """
        Extract features for defender model
        Simulates what defender would see
        """
        features = np.zeros(20)  # Match defender's expected features
        
        # Basic packet counts
        features[0] = scan_result['packets_sent']
        features[1] = scan_result['ports_scanned']
        
        # Timing
        features[2] = scan_result['avg_iat']
        features[3] = 0.1  # IAT std (simulated)
        features[4] = scan_result['packets_sent'] * scan_result['avg_iat']  # Duration
        
        # Port entropy (key indicator!)
        features[5] = scan_result['port_entropy']
        features[6] = scan_result['ports_scanned']  # Unique ports
        
        # Packet lengths (simulated)
        if scan_result['scan_type'] in ['SYN', 'FIN', 'NULL']:
            features[7] = 60  # Small packets
        else:
            features[8] = 1500  # Larger packets
        
        # Flags
        features[9] = scan_result['syn_count']
        features[10] = scan_result['fin_count']
        
        # Packet rate
        if scan_result['avg_iat'] > 0:
            features[11] = 1.0 / scan_result['avg_iat']
        
        return features
    
    def _calculate_attacker_reward(self, detected: bool, scan_result: Dict) -> float:
        """
        Calculate reward for attacker
        
        Goals:
        - Not get detected (+reward)
        - Scan efficiently (không quá chậm)
        - Cover many ports
        """
        reward = 0.0
        
        # Main goal: không bị phát hiện
        if not detected:
            reward += 10.0
        else:
            reward -= 5.0
        
        # Bonus: scan nhiều ports
        ports_bonus = scan_result['ports_scanned'] / 100.0
        reward += ports_bonus
        
        # Penalty: quá chậm
        if scan_result['avg_iat'] > 1.0:
            reward -= (scan_result['avg_iat'] - 1.0) * 2
        
        return reward
    
    def _calculate_defender_reward(self, detected: bool, scan_result: Dict) -> float:
        """
        Calculate reward for defender
        
        Goals:
        - Detect attacks (+reward)
        - Minimize false positives (không có trong simulation này)
        """
        reward = 0.0
        
        # Main goal: detect attacks
        if detected:
            reward += 10.0
        else:
            reward -= 5.0
        
        # Bonus cho early detection
        if detected and scan_result['ports_scanned'] < 20:
            reward += 5.0
        
        return reward
    
    def _format_action(self, action: Dict) -> str:
        """Format action for display"""
        return (f"Type={action.get('scan_type', 'N/A')}, "
                f"Delay={action.get('delay', 0):.2f}s, "
                f"Ports={action.get('num_ports', 0)}, "
                f"Random={action.get('randomize', False)}")
    
    def print_summary(self):
        """Print training summary"""
        print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📊 TRAINING SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        
        print(f"  Total Rounds: {self.stats['total_rounds']}")
        print(f"  Attacker Wins: {self.stats['attacker_wins']} "
              f"({self.stats['attacker_wins']/max(1, self.stats['total_rounds']):.1%})")
        print(f"  Defender Wins: {self.stats['defender_wins']} "
              f"({self.stats['defender_wins']/max(1, self.stats['total_rounds']):.1%})")
        
        if self.stats['attacker_rewards']:
            print(f"\n  Attacker Avg Reward: {np.mean(self.stats['attacker_rewards']):.2f}")
            print(f"  Defender Avg Reward: {np.mean(self.stats['defender_rewards']):.2f}")
        
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
    
    def save_history(self, filename: str):
        """Save training history"""
        with open(filename, 'w') as f:
            json.dump({
                'stats': self.stats,
                'history': self.history
            }, f, indent=2)
        print(f"  [SAVE] 💾 Training history saved to: {filename}")


class SimpleAttackerModel:
    """Simple attacker model cho training"""
    
    def __init__(self):
        self.q_table = {}  # Simple Q-learning
        self.epsilon = 0.3  # Exploration rate
        self.learning_rate = 0.1
        self.gamma = 0.9  # Discount factor
    
    def choose_action(self, state: np.ndarray) -> Dict:
        """Choose scan strategy"""
        state_key = tuple(state[:3].round(2))  # Simplified state
        
        # Epsilon-greedy
        if np.random.random() < self.epsilon:
            # Random action
            return self._random_action()
        else:
            # Best known action
            if state_key in self.q_table:
                best_action_idx = np.argmax(self.q_table[state_key])
                return self._idx_to_action(best_action_idx)
            else:
                return self._random_action()
    
    def update(self, state: np.ndarray, action: Dict, reward: float):
        """Update Q-values"""
        state_key = tuple(state[:3].round(2))
        action_idx = self._action_to_idx(action)
        
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(10)  # 10 possible actions
        
        old_q = self.q_table[state_key][action_idx]
        self.q_table[state_key][action_idx] = old_q + self.learning_rate * (reward - old_q)
    
    def _random_action(self) -> Dict:
        """Generate random action"""
        scan_types = ['SYN', 'FIN', 'NULL', 'XMAS']
        return {
            'scan_type': np.random.choice(scan_types),
            'delay': np.random.choice([0.01, 0.1, 0.5, 1.0, 2.0]),
            'num_ports': np.random.choice([10, 30, 50, 100]),
            'randomize': np.random.choice([True, False])
        }
    
    def _action_to_idx(self, action: Dict) -> int:
        """Convert action to index"""
        return hash(str(action)) % 10
    
    def _idx_to_action(self, idx: int) -> Dict:
        """Convert index to action"""
        # Simplified mapping
        delays = [0.01, 0.1, 0.5, 1.0, 2.0]
        return {
            'scan_type': 'SYN',
            'delay': delays[idx % len(delays)],
            'num_ports': 50,
            'randomize': bool(idx % 2)
        }


class SimpleDefenderModel:
    """Simple defender model cho training"""
    
    def __init__(self):
        # Simple threshold-based detection
        self.thresholds = {
            'port_entropy': 2.5,
            'packet_rate': 5.0,
            'unique_ports': 10
        }
        self.learning_rate = 0.1
    
    def predict(self, features: np.ndarray) -> int:
        """Predict if attack (1) or benign (0)"""
        port_entropy = features[5]
        unique_ports = features[6]
        
        # Simple rules
        if port_entropy > self.thresholds['port_entropy']:
            return 1  # Attack
        if unique_ports > self.thresholds['unique_ports']:
            return 1  # Attack
        
        return 0  # Benign
    
    def update(self, features: np.ndarray, is_attack: bool, reward: float):
        """Update thresholds based on feedback"""
        if reward > 0:
            # Good detection, keep thresholds
            pass
        else:
            # Missed attack or false positive, adjust
            if is_attack:
                # Missed attack - lower thresholds
                self.thresholds['port_entropy'] *= 0.95
                self.thresholds['unique_ports'] *= 0.95
            else:
                # False positive - raise thresholds
                self.thresholds['port_entropy'] *= 1.05
                self.thresholds['unique_ports'] *= 1.05


class AITrainingPlugin(BasePlugin):
    """
    Training Mode Plugin
    Allows attacker and defender AIs to fight and learn
    """
    
    def name(self) -> str:
        return "ai_training"
    
    def plugin_type(self) -> PluginType:
        return PluginType.Scan  # Run as special scan mode
    
    def register_cli(self, parse: ArgumentParser):
        group = parse.add_argument_group('AI Training Mode')
        
        group.add_argument(
            '--ai-train',
            action='store_true',
            help='Enable AI vs AI training mode'
        )
        
        group.add_argument(
            '--train-rounds',
            type=int,
            default=100,
            metavar='N',
            help='Number of training rounds (default: 100)'
        )
        
        group.add_argument(
            '--train-save',
            metavar='FILE',
            help='Save training history to file'
        )
    
    def run(self, context: ScanContext, args):
        """Run AI training"""
        if not hasattr(args, 'ai_train') or not args.ai_train:
            return
        
        print(f"\n{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}🎓 AI TRAINING MODE - Red Team vs Blue Team{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
        
        rounds = args.train_rounds if hasattr(args, 'train_rounds') else 100
        
        print(f"  Training Configuration:")
        print(f"    Rounds: {rounds}")
        print(f"    Attacker: Simple Q-Learning")
        print(f"    Defender: Threshold-based")
        print()
        
        # Initialize models
        attacker = SimpleAttackerModel()
        defender = SimpleDefenderModel()
        
        # Create training environment
        env = TrainingEnvironment(attacker, defender)
        
        # Run training rounds
        print(f"  Starting training...\n")
        
        for round_num in range(1, rounds + 1):
            result = env.run_round(round_num)
            
            # Update attacker
            state = env._get_attacker_state()
            attacker.update(state, result['attacker_action'], result['attacker_reward'])
            
            # Update defender
            features = env._extract_defender_features(result['scan_result'])
            defender.update(features, result['detected'], result['defender_reward'])
            
            # Progress
            if round_num % 10 == 0:
                print(f"\n  Progress: {round_num}/{rounds} rounds completed")
                print(f"    Current Win Rate - Attacker: "
                      f"{env.stats['attacker_wins']/round_num:.1%}, "
                      f"Defender: {env.stats['defender_wins']/round_num:.1%}")
        
        # Print summary
        env.print_summary()
        
        # Save history
        if hasattr(args, 'train_save') and args.train_save:
            env.save_history(args.train_save)
        
        # Save results to context
        context.set_data("training_results", {
            'stats': env.stats,
            'final_attacker_winrate': env.stats['attacker_wins'] / rounds,
            'final_defender_winrate': env.stats['defender_wins'] / rounds
        })
        
        print(f"\n{Fore.GREEN}✅ Training completed!{Style.RESET_ALL}\n")