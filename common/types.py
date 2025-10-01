"""
Common type definitions for analysis framework
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(Enum):
    """Severity levels for findings"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisType(Enum):
    """Types of analysis"""
    BYTECODE = "bytecode"
    SOURCECODE = "sourcecode"
    TRANSACTION = "transaction"
    COMBINED = "combined"


@dataclass
class Finding:
    """Represents a single security finding"""
    pattern_name: str
    severity: Severity
    description: str
    location: Optional[str] = None
    line_number: Optional[int] = None
    matched_text: Optional[str] = None
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Result from a single pattern analysis"""
    pattern_name: str
    findings: List[Finding]
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Complete analysis report"""
    analysis_type: AnalysisType
    target_hash: str
    contract_name: str
    results: List[AnalysisResult]
    total_execution_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[float] = None
