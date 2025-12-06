"""
AI Attacker Agent - DQN-based evasion controller
"""
import torch
import torch.nn as nn
import numpy as np
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional


class DQN(nn.Module):
    """
    Deep Q-Network Architecture
    MUST match training code exactly!
    """
    def __init__(self, state_dim: int, action_dims: List[int]):
        super(DQN, self).__init__()
        self.action_dims = action_dims
        
        # Shared layers
        self.fc1 = nn.Linear(state_dim, 128)
        self.fc2 = nn.Linear(128, 128)
        
        # Separate heads for each action dimension
        self.action_heads = nn.ModuleList([
            nn.Linear(128, dim) for dim in action_dims
        ])
    
    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        q_values = [head(x) for head in self.action_heads]
        return q_values


class AIAttackerAgent:
    """
    AI-powered port scan evasion agent using Deep Q-Learning.
    Adapts scan strategy in real-time to avoid detection.
    """
    
    # Strategy mappings (must match training)
    TIMING_STRATEGIES = ['slow', 'medium', 'fast']
    PORT_ORDER_STRATEGIES = ['sequential', 'random', 'common_first']
    
    def __init__(self, model_dir: str = None, verbose: bool = False):
        """
        Initialize AI Attacker Agent.
        
        Args:
            model_dir: Directory containing trained model files
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Default model directory
        if model_dir is None:
            model_dir = Path(__file__).parent / 'models'
        else:
            model_dir = Path(model_dir)
        
        # Load metadata
        metadata_path = model_dir / 'attacker_metadata.json'
        if not metadata_path.exists():
            raise FileNotFoundError(f"Model metadata not found: {metadata_path}")
        
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        # Initialize Q-Network
        self.state_dim = self.metadata['state_dim']
        self.action_dims = self.metadata['action_dims']
        
        self.q_network = DQN(self.state_dim, self.action_dims).to(self.device)
        
        # Load trained weights
        model_path = model_dir / 'attacker_ai_q_network.pth'
        if not model_path.exists():
            raise FileNotFoundError(f"Model weights not found: {model_path}")
        
        self.q_network.load_state_dict(
            torch.load(model_path, map_location=self.device)
        )
        self.q_network.eval()
        
        if self.verbose:
            print(f"[AI-Attacker] Loaded successfully")
            print(f"  Device: {self.device}")
            print(f"  Training success rate: {self.metadata['evaluation']['success_rate']:.1%}")
        
        # Internal state tracking
        self.reset()
    
    def reset(self):
        """Reset agent state for new scan"""
        self.ports_scanned = 0
        self.total_ports = 100
        self.detected_count = 0
        self.detection_history = [0] * 5  # Last 5 detection events
        self.confidence_history = []
        self.step_count = 0
        self.current_strategy = None
    
    def get_observation(self) -> np.ndarray:
        """
        Generate observation vector from current state.
        Must match training observation space!
        
        Observation: [progress, detected_count/10, *detection_history(5), 
                      avg_confidence, avg_stealth, step_count/20]
        """
        progress = self.ports_scanned / max(self.total_ports, 1)
        
        # Average confidence from last 3 observations
        avg_confidence = (
            np.mean(self.confidence_history[-3:]) 
            if self.confidence_history else 0.0
        )
        
        # Estimate stealth based on current strategy
        avg_stealth = self._estimate_stealth()
        
        obs = np.array([
            progress,
            self.detected_count / 10.0,
            *self.detection_history,
            avg_confidence,
            avg_stealth,
            self.step_count / 20.0
        ], dtype=np.float32)
        
        return obs
    
    def select_action(self, observation: np.ndarray = None) -> List[int]:
        """
        Select optimal action using trained Q-network (greedy policy).
        
        Returns:
            List[int]: [timing_idx, port_order_idx, packet_variation, ttl_random]
        """
        if observation is None:
            observation = self.get_observation()
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(observation).unsqueeze(0).to(self.device)
            q_values_list = self.q_network(state_tensor)
            
            # Greedy action selection (no exploration)
            actions = [q_vals.argmax().item() for q_vals in q_values_list]
        
        return actions
    
    def action_to_strategy(self, action: List[int]) -> Dict:
        """
        Convert DQN action indices to concrete scan strategy.
        
        Args:
            action: [timing, port_order, packet_variation, ttl_randomization]
        
        Returns:
            Strategy dict with parameters
        """
        strategy = {
            'timing': self.TIMING_STRATEGIES[action[0]],
            'port_order': self.PORT_ORDER_STRATEGIES[action[1]],
            'packet_size_variation': action[2] / 10.0,  # Normalize to [0, 1]
            'ttl_randomization': bool(action[3])
        }
        
        return strategy
    
    def get_strategy(self) -> Dict:
        """
        Get next optimal scan strategy based on current state.
        
        Returns:
            Strategy dict with scan parameters
        """
        observation = self.get_observation()
        action = self.select_action(observation)
        strategy = self.action_to_strategy(action)
        
        self.current_strategy = strategy
        
        if self.verbose and self.step_count % 5 == 0:
            print(f"  [AI-Strategy] Step {self.step_count}: "
                  f"Timing={strategy['timing']}, "
                  f"Order={strategy['port_order']}, "
                  f"Detections={self.detected_count}")
        
        return strategy
    
    def update_state(self, ports_scanned: int, detected: bool = False, 
                    confidence: float = 0.0):
        """
        Update internal state after scan batch.
        
        Args:
            ports_scanned: Number of new ports scanned
            detected: Whether detection occurred
            confidence: Defender confidence score (0-1)
        """
        self.ports_scanned += ports_scanned
        self.step_count += 1
        
        # Update detection history (shift left, add new)
        self.detection_history.pop(0)
        self.detection_history.append(1 if detected else 0)
        
        if detected:
            self.detected_count += 1
        
        # Track confidence
        if confidence > 0:
            self.confidence_history.append(confidence)
    
    def should_abort(self, max_detections: int = 5) -> bool:
        """
        Determine if scan should be aborted due to too many detections.
        
        Args:
            max_detections: Maximum allowed detections before abort
            
        Returns:
            bool: True if scan should abort
        """
        return self.detected_count >= max_detections
    
    def get_stats(self) -> Dict:
        """Get current agent statistics"""
        return {
            'ports_scanned': self.ports_scanned,
            'total_ports': self.total_ports,
            'detected_count': self.detected_count,
            'step_count': self.step_count,
            'current_strategy': self.current_strategy,
            'should_abort': self.should_abort()
        }
    
    def _estimate_stealth(self) -> float:
        """
        Estimate current stealth level based on strategy.
        Higher = more stealthy (slower, more random)
        """
        if not self.current_strategy:
            return 0.5
        
        stealth_score = 0.0
        
        # Timing contributes 40%
        timing_scores = {'slow': 1.0, 'medium': 0.5, 'fast': 0.0}
        stealth_score += timing_scores.get(self.current_strategy['timing'], 0.5) * 0.4
        
        # Port order contributes 30%
        order_scores = {'random': 1.0, 'common_first': 0.5, 'sequential': 0.0}
        stealth_score += order_scores.get(self.current_strategy['port_order'], 0.5) * 0.3
        
        # Packet variation contributes 20%
        stealth_score += self.current_strategy['packet_size_variation'] * 0.2
        
        # TTL randomization contributes 10%
        stealth_score += (1.0 if self.current_strategy['ttl_randomization'] else 0.0) * 0.1
        
        return stealth_score