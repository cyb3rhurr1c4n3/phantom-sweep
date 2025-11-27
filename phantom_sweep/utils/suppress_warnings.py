"""Suppress all unwanted warnings"""
import warnings
import os
import sys
import logging

def suppress_all_warnings():
    """Suppress sklearn, numpy, and other library warnings"""
    # Python warnings
    warnings.filterwarnings('ignore')
    warnings.simplefilter('ignore')
    
    # Environment variables
    os.environ['PYTHONWARNINGS'] = 'ignore'
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    
    # Logging
    logging.getLogger('sklearn').setLevel(logging.ERROR)
    logging.getLogger('numpy').setLevel(logging.ERROR)
    logging.getLogger('joblib').setLevel(logging.ERROR)
    
    # Stderr redirection for parallel output
    sys.stderr = open(os.devnull, 'w')