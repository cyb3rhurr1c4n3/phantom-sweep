
from phantom_sweep.module.analyzer.detect_os_plugin import AIOSFingerprinter


# QUAN TRỌNG: Thêm vào registry
OS_FINGERPRINTING_ANALYZERS = {
    'ai': AIOSFingerprinter,
}
__all__ = [
    'AIOSFingerprinter'
]