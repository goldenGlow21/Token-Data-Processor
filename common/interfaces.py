"""
Base interfaces for analyzers and patterns
"""

from abc import ABC, abstractmethod
from typing import List, Any
from .types import Finding, AnalysisResult, AnalysisReport


class BasePattern(ABC):
    """Base class for all analysis patterns"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Pattern name"""
        pass

    @abstractmethod
    def analyze(self, target: Any) -> List[Finding]:
        """
        Analyze target and return findings

        Args:
            target: The target to analyze (source code, bytecode, etc.)

        Returns:
            List of findings
        """
        pass


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""

    def __init__(self):
        self.patterns: List[BasePattern] = []
        self._register_patterns()

    @abstractmethod
    def _register_patterns(self) -> None:
        """Register analysis patterns"""
        pass

    @abstractmethod
    def analyze(self, target: Any, **kwargs) -> AnalysisReport:
        """
        Analyze target and generate report

        Args:
            target: The target to analyze
            **kwargs: Additional parameters

        Returns:
            Analysis report
        """
        pass

    def _run_pattern_analysis(self, pattern: BasePattern, target: Any) -> AnalysisResult:
        """
        Run a single pattern analysis with error handling

        Args:
            pattern: Pattern to run
            target: Target to analyze

        Returns:
            Analysis result
        """
        import time

        start_time = time.time()

        try:
            findings = pattern.analyze(target)
            execution_time = time.time() - start_time

            return AnalysisResult(
                pattern_name=pattern.name,
                findings=findings,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time

            return AnalysisResult(
                pattern_name=pattern.name,
                findings=[],
                execution_time=execution_time,
                error=str(e)
            )