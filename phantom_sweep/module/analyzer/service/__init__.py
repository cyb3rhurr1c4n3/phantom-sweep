"""
Analyzer Module - Service detection analyzers
"""
from phantom_sweep.module.analyzer.service.service_detection_normal import NormalServiceDetection
from phantom_sweep.module.analyzer.service.service_detection_ai import AIServiceDetection

# Service Detection Analyzers Registry
SERVICE_DETECTION_ANALYZERS = {
    "normal": NormalServiceDetection,
    "ai": AIServiceDetection,
    "off": None,
}

__all__ = [
    'NormalServiceDetection',
    'AIServiceDetection',
    'SERVICE_DETECTION_ANALYZERS',
]