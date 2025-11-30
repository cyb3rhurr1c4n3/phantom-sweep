from phantom_sweep.module.analyzer.os.detect_os_plugin import AIOSFingerprinter, NormalOSFingerprinter


OS_FINGERPRINTING_ANALYZERS = {
    "normal": NormalOSFingerprinter,
    "ai": AIOSFingerprinter,
    "off": None,
}

__all__ = [
    'OS_FINGERPRINTING_ANALYZERS'
]