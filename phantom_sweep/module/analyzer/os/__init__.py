"""
Analyzer Module - Service detection and OS fingerprinting analyzers
"""




# OS Fingerprinting Analyzers Registry
from phantom_sweep.module.analyzer.os.detect_os_plugin import AIOSFingerprinter


OS_FINGERPRINTING_ANALYZERS = {
    "normal": None,
    "ai": AIOSFingerprinter,
    "off": None,
}

__all__ = [
    'OS_FINGERPRINTING_ANALYZERS'
]