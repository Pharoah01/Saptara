"""
Shared data models for the security testing suite
"""

from .test_result import TestResult, TestStatus, VulnerabilityLevel
from .scan_config import ScanConfig, TestCategory, IntensityLevel
from .target import Target, TargetType

__all__ = [
    'TestResult',
    'TestStatus', 
    'VulnerabilityLevel',
    'ScanConfig',
    'TestCategory',
    'IntensityLevel',
    'Target',
    'TargetType'
]