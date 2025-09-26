"""
Common types and interfaces for the Ethereum Analysis System
"""

from .types import Finding, AnalysisResult, AnalysisReport, Severity
from .interfaces import BaseAnalyzer, BasePattern

__all__ = [
    'Finding', 'AnalysisResult', 'AnalysisReport', 'Severity',
    'BaseAnalyzer', 'BasePattern'
]