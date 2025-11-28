"""
Strategy Mapper - Convert AI decisions to scan parameters
"""
import random
from typing import List, Dict, Tuple


class StrategyMapper:
    """
    Maps AI strategy decisions to concrete scan parameters.
    Bridges the gap between abstract AI actions and real network operations.
    """
    
    @staticmethod
    def get_timing_params(timing: str) -> Dict[str, float]:
        """
        Map timing strategy to scan parameters.
        
        Args:
            timing: 'slow', 'medium', or 'fast'
            
        Returns:
            Dict with 'delay' and 'timeout' parameters
        """
        timing_configs = {
            'slow': {
                'delay': 1.0,      # 1 second between packets
                'timeout': 5.0,    # 5 second timeout
                'batch_size': 5    # Small batches
            },
            'medium': {
                'delay': 0.1,      # 0.1 second between packets
                'timeout': 3.0,    # 3 second timeout
                'batch_size': 10
            },
            'fast': {
                'delay': 0.01,     # 0.01 second between packets
                'timeout': 2.0,    # 2 second timeout
                'batch_size': 20
            }
        }
        
        return timing_configs.get(timing, timing_configs['medium'])
    
    @staticmethod
    def get_port_sequence(port_order: str, ports: List[int]) -> List[int]:
        """
        Map port order strategy to actual port sequence.
        
        Args:
            port_order: 'sequential', 'random', or 'common_first'
            ports: List of ports to scan
            
        Returns:
            Reordered port list
        """
        if port_order == 'sequential':
            return sorted(ports)
        
        elif port_order == 'random':
            shuffled = ports.copy()
            random.shuffle(shuffled)
            return shuffled
        
        elif port_order == 'common_first':
            # Common ports that are often open
            common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389, 8080, 8443]
            
            # Separate into common and uncommon
            common = [p for p in common_ports if p in ports]
            uncommon = [p for p in ports if p not in common]
            
            # Randomize uncommon ports
            random.shuffle(uncommon)
            
            return common + uncommon
        
        return ports
    
    @staticmethod
    def get_packet_params(packet_size_variation: float, 
                         ttl_randomization: bool) -> Dict:
        """
        Map packet manipulation parameters to Scapy parameters.
        
        Args:
            packet_size_variation: 0.0-1.0, higher = more variation
            ttl_randomization: Whether to randomize TTL
            
        Returns:
            Dict with packet manipulation parameters
        """
        params = {}
        
        # Packet size variation via TCP options padding
        if packet_size_variation > 0.5:
            # Add random TCP NOP options for padding
            num_nops = int(packet_size_variation * 20)
            params['tcp_options'] = [('NOP', None)] * num_nops
        else:
            params['tcp_options'] = []
        
        # TTL randomization
        if ttl_randomization:
            params['ttl'] = random.randint(64, 128)
        else:
            params['ttl'] = 64  # Standard Linux TTL
        
        # Randomize TCP window size (subtle evasion)
        if packet_size_variation > 0.3:
            params['window'] = random.choice([
                1024, 2048, 4096, 8192, 16384, 29200, 65535
            ])
        else:
            params['window'] = 8192  # Standard
        
        return params
    
    @staticmethod
    def apply_strategy_to_config(strategy: Dict, ports: List[int]) -> Dict:
        """
        Apply complete AI strategy to scan configuration.
        
        Args:
            strategy: Strategy dict from AI agent
            ports: List of ports to scan
            
        Returns:
            Complete scan config with all parameters
        """
        # Get timing parameters
        timing_params = StrategyMapper.get_timing_params(strategy['timing'])
        
        # Reorder ports
        port_sequence = StrategyMapper.get_port_sequence(
            strategy['port_order'], 
            ports
        )
        
        # Get packet manipulation parameters
        packet_params = StrategyMapper.get_packet_params(
            strategy['packet_size_variation'],
            strategy['ttl_randomization']
        )
        
        # Combine into complete config
        scan_config = {
            'ports': port_sequence,
            'inter_delay': timing_params['delay'],
            'timeout': timing_params['timeout'],
            'batch_size': timing_params['batch_size'],
            'ttl': packet_params['ttl'],
            'tcp_options': packet_params['tcp_options'],
            'window': packet_params.get('window', 8192)
        }
        
        return scan_config