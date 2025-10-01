"""
Common interfaces for analyzers and patterns
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from .types import AnalysisReport, Finding


class BasePattern(ABC):
    """Base class for detection patterns"""

    @abstractmethod
    def detect(self, data: str) -> List[Finding]:
        """
        Detect pattern in given data

        Args:
            data: Data to analyze (bytecode, source code, etc.)

        Returns:
            List of findings
        """
        pass


class BaseAnalyzer(ABC):
    """Base class for analyzers"""

    def __init__(self):
        self.patterns: List[BasePattern] = []
        self._register_patterns()

    @abstractmethod
    def _register_patterns(self) -> None:
        """Register patterns to be used in analysis"""
        pass

    @abstractmethod
    def analyze(self, data: str, **kwargs) -> AnalysisReport:
        """
        Analyze given data

        Args:
            data: Data to analyze
            **kwargs: Additional parameters

        Returns:
            Analysis report
        """
        pass
