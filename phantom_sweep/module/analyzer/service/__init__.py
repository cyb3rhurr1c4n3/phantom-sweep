"""
Analyzer Module - Service detection and OS fingerprinting analyzers
"""
from phantom_sweep.module.analyzer.service.service_detection_normal import NormalServiceDetection
from phantom_sweep.module.analyzer.service.service_detection_ai import AIServiceDetection

# Service Detection Analyzers Registry
SERVICE_DETECTION_ANALYZERS = {
    "normal": NormalServiceDetection,
    "ai": AIServiceDetection,
    "off": None,
}

# OS Fingerprinting Analyzers Registry
OS_FINGERPRINTING_ANALYZERS = {
    "normal": None,
    "ai": None,
    "off": None,
}

__all__ = [
    'NormalServiceDetection',
    'AIServiceDetection',
    'SERVICE_DETECTION_ANALYZERS',
    'OS_FINGERPRINTING_ANALYZERS',
]