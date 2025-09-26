"""
Common data types used across the analysis system
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum


class Severity(Enum):
    """Security issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalysisType(Enum):
    """Type of analysis performed"""
    SOURCE_CODE = "source_code"
    BYTECODE = "bytecode"
    MIXED = "mixed"


@dataclass
class Finding:
    """A security finding detected during analysis"""
    pattern_name: str
    description: str
    severity: Severity = Severity.MEDIUM
    recommendation: str = ""

    # Location information
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: Optional[str] = None
    selector: Optional[str] = None

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format"""
        return {
            "pattern_name": self.pattern_name,
            "description": self.description,
            "severity": self.severity.value,
            "recommendation": self.recommendation,
            "location": {
                "line_number": self.line_number,
                "function_name": self.function_name,
                "code_snippet": self.code_snippet,
                "selector": self.selector
            },
            "metadata": self.metadata
        }


@dataclass
class AnalysisResult:
    """Result of a single pattern analysis"""
    pattern_name: str
    findings: List[Finding]
    execution_time: float = 0.0
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        """Get total number of findings"""
        return len(self.findings)

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Get counts by severity"""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


@dataclass
class AnalysisReport:
    """Complete analysis report"""
    analysis_type: AnalysisType
    target_hash: str
    contract_name: str = "Unknown"

    # Analysis results
    results: List[AnalysisResult] = field(default_factory=list)
    total_execution_time: float = 0.0

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings from all results"""
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    @property
    def total_issues(self) -> int:
        """Get total number of issues found"""
        return len(self.all_findings)

    @property
    def pattern_counts(self) -> Dict[str, int]:
        """Get pattern occurrence counts"""
        counts = {}
        for finding in self.all_findings:
            counts[finding.pattern_name] = counts.get(finding.pattern_name, 0) + 1
        return counts

    @property
    def severity_distribution(self) -> Dict[str, int]:
        """Get severity distribution"""
        distribution = {severity.value: 0 for severity in Severity}
        for finding in self.all_findings:
            distribution[finding.severity.value] += 1
        return distribution

    @property
    def risk_score(self) -> int:
        """Calculate risk score based on findings"""
        return self._calculate_risk_score()

    def _calculate_risk_score(self) -> int:
        """Calculate risk score based on pattern weights"""
        # Pattern weight coefficients based on maliciousness likelihood
        pattern_weights = {
            # Critical patterns
            'Direct Balance Assignment': 20.0,
            'Balance Manipulation': 18.0,
            'Asymmetric Fee Structure': 15.0,

            # High risk patterns
            'Reentrancy Vulnerability': 10.0,
            'Self Destruct': 8.0,
            'Delegate Call': 6.0,
            'Metamorphic Contract': 5.0,

            # Medium risk patterns
            'Approve Function Manipulation': 3.0,
            'Hidden Minting': 2.0,
            'Unlimited Token Issuance': 2.0,
            'Unlimited Minting': 2.0,
            'Sell-Path Block': 1.5,
            'Transfer Restriction': 1.5,
            'Fee Manipulation': 1.5,

            # Low risk patterns
            'Contract Pause Abuse': 1.0,
            'Pause Abuse': 1.0,
            'Pausable Exit Block': 0.8,
            'Admin Abuse': 0.5,
            'Total Supply Manipulation': 0.5,
            'Owner Pause Bypass': 0.3,
            'Permanent Owner Control': 0.2,
            'Execution Order Dependency': 0.1,
            'Missing Event': 0.1
        }

        base_score = 100
        total_weighted_issues = 0

        pattern_counts = self.pattern_counts
        for pattern_name, count in pattern_counts.items():
            if pattern_name in pattern_weights and count > 0:
                weight = pattern_weights[pattern_name]
                total_weighted_issues += weight

        if total_weighted_issues > 0:
            if total_weighted_issues <= 5:
                score_deduction = total_weighted_issues * 3
            elif total_weighted_issues <= 15:
                score_deduction = 15 + (total_weighted_issues - 5) * 2
            else:
                score_deduction = 35 + (total_weighted_issues - 15) * 3

            score_deduction = min(80, score_deduction)
            base_score = int(base_score - score_deduction)

        return max(0, base_score)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format"""
        return {
            "category": "STE",
            "analysis_score": self.risk_score,
            "analysis_type": self.analysis_type.value,
            "source_hash": self.target_hash,
            "contract_name": self.contract_name,
            "summary": {
                "total_issues": self.total_issues,
                "pattern_counts": self.pattern_counts,
                "severity_distribution": self.severity_distribution,
                "execution_time": self.total_execution_time
            },
            "findings": [finding.to_dict() for finding in self.all_findings],
            "metadata": self.metadata
        }