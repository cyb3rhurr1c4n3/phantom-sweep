"""
Analyzer Module - Service Detection and OS Fingerprinting
"""
# TODO: Import analyzer implementations when they are created
# from phantom_sweep.module.analyzer.service_detection import (
#     ServiceDetectionNormal, ServiceDetectionAI
# )
# from phantom_sweep.module.analyzer.os_fingerprinting import (
#     OSFingerprintingNormal, OSFingerprintingAI
# )

# Analyzer registry
# Format: {mode: AnalyzerClass}
SERVICE_DETECTION_ANALYZERS = {
    # "normal": ServiceDetectionNormal,
    # "ai": ServiceDetectionAI,
}

OS_FINGERPRINTING_ANALYZERS = {
    # "normal": OSFingerprintingNormal,
    # "ai": OSFingerprintingAI,
}

__all__ = [
    'SERVICE_DETECTION_ANALYZERS', 'OS_FINGERPRINTING_ANALYZERS'
]

