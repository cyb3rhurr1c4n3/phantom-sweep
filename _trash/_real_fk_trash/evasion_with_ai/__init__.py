"""
AI Module for PhantomSweep
"""
try:
    from phantom_sweep.module.scanner.port_scanning.ai.attacker_agent  import AIAttackerAgent
    from phantom_sweep.module.scanner.port_scanning.ai.strategy_mapper import StrategyMapper
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

__all__ = ['AIAttackerAgent', 'StrategyMapper', 'AI_AVAILABLE']