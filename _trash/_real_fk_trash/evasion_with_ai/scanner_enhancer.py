"""
AI Scanner Enhancer - Mixin for adding AI evasion to scanners
"""
import torch
import numpy as np
from typing import Dict, List, Optional
import os


class AIScannerEnhancer:
    """Mixin class to add AI-powered evasion capabilities to scanners."""
    
    def __init__(self):
        self.ai_enabled = False
        self.ai_agent = None
        self.ai_stats = {
            'ports_scanned': 0,
            'total_ports': 0,
            'detected_count': 0,
            'detection_history': [],
            'should_abort': False
        }
    
    def enable_ai(self, model_path: str = 'models/attacker_ai_q_network.pth', verbose: bool = False) -> bool:
        """Enable AI evasion mode"""
        try:
            from phantom_sweep.module.scanner.port_scanning.ai.attacker_agent import AIAttackerAgent
            
            if not os.path.exists(model_path):
                if verbose:
                    print(f"[AI] Model not found: {model_path}")
                return False
            
            self.ai_agent = AIAttackerAgent(model_path, verbose=verbose)
            self.ai_enabled = True
            
            if verbose:
                print("[AI] ✓ AI evasion enabled")
            
            return True
            
        except Exception as e:
            if verbose:
                print(f"[AI] ✗ Failed to enable AI: {e}")
            return False
    
    def init_ai_for_scan(self, total_ports: int, verbose: bool = False):
        """Initialize AI state for new scan"""
        if not self.ai_enabled or not self.ai_agent:
            return
        
        self.ai_agent.reset()
        self.ai_agent.total_ports = total_ports
        self.ai_stats['total_ports'] = total_ports
        self.ai_stats['ports_scanned'] = 0
        self.ai_stats['detected_count'] = 0
        
        if verbose:
            print(f"[AI] Initialized for {total_ports} ports")
    
    def get_ai_strategy(self) -> Optional[Dict]:
        """Get AI-recommended strategy"""
        if not self.ai_enabled or not self.ai_agent:
            return None
        
        return self.ai_agent.get_strategy()
    
    def apply_ai_strategy(self, strategy: Optional[Dict], ports: List[int]) -> Dict:
        """Apply AI strategy to scan configuration"""
        from phantom_sweep.module.scanner.port_scanning.ai.strategy_mapper import StrategyMapper
        
        if strategy is None:
            return {
                'ports': ports,
                'batch_size': 10,
                'inter_delay': 0.1,
                'timeout': 3.0,
                'ttl': 64,
                'window': 8192,
                'tcp_options': []
            }
        
        # Use StrategyMapper methods
        return StrategyMapper.apply_strategy_to_config(strategy, ports)
    
    def update_ai_state(self, ports_scanned: int, detected: bool, confidence: float = 0.0):
        """Update AI state after scanning"""
        if not self.ai_enabled or not self.ai_agent:
            return
        
        self.ai_agent.update_state(ports_scanned, detected, confidence)
        self.ai_stats['ports_scanned'] += ports_scanned
        
        if detected:
            self.ai_stats['detected_count'] += 1
        
        if self.ai_agent.should_abort():
            self.ai_stats['should_abort'] = True
    
    def should_ai_abort(self) -> bool:
        """Check if AI recommends aborting scan"""
        if not self.ai_enabled or not self.ai_agent:
            return False
        
        return self.ai_agent.should_abort()
    
    def get_ai_stats(self) -> Dict:
        """Get AI statistics"""
        if self.ai_agent:
            return self.ai_agent.get_stats()
        return self.ai_stats.copy()