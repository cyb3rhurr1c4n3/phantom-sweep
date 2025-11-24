"""
AI Scanner Enhancer - Mixin for adding AI capabilities to any scanner
"""
from typing import List, Dict, Optional
from phantom_sweep.ai.attacker_agent import AIAttackerAgent
from phantom_sweep.ai.strategy_mapper import StrategyMapper


class AIScannerEnhancer:
    """
    Mixin class that adds AI evasion capabilities to any scanner.
    Can be used with TCP SYN, TCP Connect, or UDP scanners.
    """
    
    def __init__(self):
        self.ai_agent: Optional[AIAttackerAgent] = None
        self.ai_enabled = False
        self.strategy_mapper = StrategyMapper()
    
    def enable_ai(self, verbose: bool = False) -> bool:
        """
        Enable AI evasion mode.
        
        Returns:
            bool: True if successfully enabled, False otherwise
        """
        try:
            self.ai_agent = AIAttackerAgent(verbose=verbose)
            self.ai_enabled = True
            if verbose:
                print("[AI] Evasion mode: ENABLED ✓")
            return True
        except Exception as e:
            if verbose:
                print(f"[AI] Failed to enable: {e}")
                print("[AI] Falling back to normal mode")
            self.ai_enabled = False
            return False
    
    def init_ai_for_scan(self, total_ports: int, verbose: bool = False):
        """Initialize AI agent for new scan"""
        if self.ai_enabled and self.ai_agent:
            self.ai_agent.reset()
            self.ai_agent.total_ports = total_ports
            if verbose:
                print(f"[AI] Initialized for {total_ports} ports")
    
    def get_ai_strategy(self) -> Optional[Dict]:
        """Get next AI strategy"""
        if self.ai_enabled and self.ai_agent:
            return self.ai_agent.get_strategy()
        return None
    
    def apply_ai_strategy(self, strategy: Dict, ports: List[int]) -> Dict:
        """Apply AI strategy to get scan config"""
        if not strategy:
            # Return default config
            return {
                'ports': ports,
                'inter_delay': 0.01,
                'timeout': 2.0,
                'batch_size': 50,
                'ttl': 64,
                'tcp_options': [],
                'window': 8192
            }
        
        return self.strategy_mapper.apply_strategy_to_config(strategy, ports)
    
    def update_ai_state(self, ports_scanned: int, detected: bool = False, 
                       confidence: float = 0.0):
        """Update AI state after scan batch"""
        if self.ai_enabled and self.ai_agent:
            self.ai_agent.update_state(ports_scanned, detected, confidence)
    
    def should_ai_abort(self) -> bool:
        """Check if AI recommends aborting scan"""
        if self.ai_enabled and self.ai_agent:
            return self.ai_agent.should_abort()
        return False
    
    def get_ai_stats(self) -> Optional[Dict]:
        """Get AI statistics"""
        if self.ai_enabled and self.ai_agent:
            return self.ai_agent.get_stats()
        return None
    
    def reorder_ports_by_strategy(self, ports: List[int], strategy: Optional[Dict]) -> List[int]:
        """Reorder ports based on AI strategy"""
        if not strategy:
            return ports
        
        return self.strategy_mapper.get_port_sequence(
            strategy['port_order'], 
            ports
        )
    
    def get_timing_params(self, strategy: Optional[Dict]) -> Dict:
        """Get timing parameters from strategy"""
        if not strategy:
            return {'delay': 0.01, 'timeout': 2.0, 'batch_size': 50}
        
        return self.strategy_mapper.get_timing_params(strategy['timing'])
    
    def get_packet_params(self, strategy: Optional[Dict]) -> Dict:
        """Get packet manipulation parameters from strategy"""
        if not strategy:
            return {'ttl': 64, 'tcp_options': [], 'window': 8192}
        
        return self.strategy_mapper.get_packet_params(
            strategy['packet_size_variation'],
            strategy['ttl_randomization']
        )