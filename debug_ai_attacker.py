"""
Debug AI Attacker Strategies
"""
import sys
sys.path.append('phantom_sweep')

from phantom_sweep.module.scanner.port_scanning.ai.attacker_agent import AIAttackerAgent
import numpy as np


def analyze_ai_strategies():
    """Analyze what strategies AI has learned"""
    
    print("="*60)
    print("AI ATTACKER STRATEGY ANALYSIS")
    print("="*60)
    
    # Load AI agent
    agent = AIAttackerAgent(verbose=True)
    
    print("\n[*] Testing AI decisions at different scan stages...")
    
    # Simulate different scan scenarios
    scenarios = [
        {
            'name': 'Start of scan (no detections)',
            'ports_scanned': 0,
            'detected_count': 0,
            'detection_history': [0, 0, 0, 0, 0]
        },
        {
            'name': 'Mid scan (1 detection)',
            'ports_scanned': 30,
            'detected_count': 1,
            'detection_history': [0, 0, 1, 0, 0]
        },
        {
            'name': 'Heavy detection (3 detections)',
            'ports_scanned': 50,
            'detected_count': 3,
            'detection_history': [1, 0, 1, 1, 0]
        },
        {
            'name': 'Critical (5 detections)',
            'ports_scanned': 60,
            'detected_count': 5,
            'detection_history': [1, 1, 1, 1, 1]
        }
    ]
    
    for scenario in scenarios:
        print(f"\n{'='*60}")
        print(f"Scenario: {scenario['name']}")
        print(f"{'='*60}")
        
        # Set agent state
        agent.reset()
        agent.total_ports = 100
        agent.ports_scanned = scenario['ports_scanned']
        agent.detected_count = scenario['detected_count']
        agent.detection_history = scenario['detection_history']
        
        # Get observation
        obs = agent.get_observation()
        print(f"\nObservation: {obs}")
        
        # Get action
        action = agent.select_action(obs)
        print(f"Action (indices): {action}")
        
        # Convert to strategy
        strategy = agent.action_to_strategy(action)
        print(f"\nStrategy:")
        print(f"  Timing: {strategy['timing']}")
        print(f"  Port Order: {strategy['port_order']}")
        print(f"  Packet Variation: {strategy['packet_size_variation']:.2f}")
        print(f"  TTL Randomization: {strategy['ttl_randomization']}")
        
        # Calculate stealth score
        stealth = agent._estimate_stealth()
        print(f"  Estimated Stealth: {stealth:.2f}")
        
        # Check if should abort
        if agent.should_abort():
            print(f"\n⚠️  AI recommends ABORT")
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)


def test_strategy_effectiveness():
    """Test how effective each strategy is"""
    
    print("\n" + "="*60)
    print("STRATEGY EFFECTIVENESS TEST")
    print("="*60)
    
    strategies = {
        'aggressive': {
            'timing': 'fast',
            'port_order': 'sequential',
            'packet_size_variation': 0.0,
            'ttl_randomization': False
        },
        'balanced': {
            'timing': 'medium',
            'port_order': 'random',
            'packet_size_variation': 0.5,
            'ttl_randomization': True
        },
        'stealthy': {
            'timing': 'slow',
            'port_order': 'random',
            'packet_size_variation': 1.0,
            'ttl_randomization': True
        }
    }
    
    print("\nExpected Detection Probabilities:")
    print("-" * 60)
    
    for name, strategy in strategies.items():
        # Estimate detection probability based on strategy
        detection_prob = 0.1  # Base
        
        if strategy['timing'] == 'fast':
            detection_prob *= 3.0
        elif strategy['timing'] == 'medium':
            detection_prob *= 1.5
        else:  # slow
            detection_prob *= 0.5
        
        if strategy['port_order'] == 'sequential':
            detection_prob *= 1.5
        
        if not strategy['ttl_randomization']:
            detection_prob *= 1.2
        
        print(f"{name.upper():12} → Detection Prob: {detection_prob*100:.1f}%")
    
    print("\n💡 Recommendation:")
    print("   - Use 'stealthy' strategy against strong defenders")
    print("   - Use 'balanced' for normal scenarios")
    print("   - Use 'aggressive' only for speed (high risk)")


if __name__ == "__main__":
    analyze_ai_strategies()
    test_strategy_effectiveness()