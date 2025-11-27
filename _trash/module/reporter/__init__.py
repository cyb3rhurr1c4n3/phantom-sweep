"""
Reporter Module - Output Formatters
"""
from phantom_sweep.module.reporter.text_reporter import TextReporter
from phantom_sweep.module.reporter.json_reporter import JSONReporter
# TODO: Import other reporter implementations when they are created
# from phantom_sweep.module.reporter.xml_reporter import XMLReporter
# from phantom_sweep.module.reporter.csv_reporter import CSVReporter

# Reporter registry
# Format: {format_name: ReporterClass}
REPORTERS = {
    "text": TextReporter,
    "json": JSONReporter,
    # "xml": XMLReporter,
    # "csv": CSVReporter,
}

__all__ = ['REPORTERS', 'TextReporter', 'JSONReporter']

