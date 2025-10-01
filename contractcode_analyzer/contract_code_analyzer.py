#!/usr/bin/env python3
"""
Contract Code Analyzer
스마트 컨트랙트 소스코드 분석 도구

소스코드를 분석하여 scam 패턴과 보안 취약점을 탐지합니다.
"""

import time
import hashlib
from typing import List, Dict, Any
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from contractcode_analyzer.analyzer.STE0101_1 import STE0101_1_Analyzer
from contractcode_analyzer.analyzer.STE0101_2 import STE0101_2_Analyzer
from contractcode_analyzer.analyzer.STE0101_3 import STE0101_3_Analyzer
from contractcode_analyzer.analyzer.STE0103 import STE0103_Analyzer
from contractcode_analyzer.analyzer.STE0104 import STE0104_Analyzer
from contractcode_analyzer.analyzer.STE0105 import STE0105_Analyzer


class ContractCodeAnalyzer:
    """Main contract code analyzer that coordinates all STE analyzers"""

    def __init__(self):
        """Initialize all STE analyzers"""
        self.analyzers = [
            STE0101_1_Analyzer(),
            STE0101_2_Analyzer(),
            STE0101_3_Analyzer(),
            STE0103_Analyzer(),
            STE0104_Analyzer(),
            STE0105_Analyzer()
        ]

        self.risk_levels = {
            (0, 20): "LOW_RISK",
            (21, 40): "MEDIUM_RISK",
            (41, 60): "HIGH_RISK",
            (61, 80): "VERY_HIGH_RISK",
            (81, 100): "CRITICAL_RISK"
        }

    def _preprocess_code(self, contract_code: str) -> str:
        """Preprocess contract code for analysis"""
        # Remove comments
        import re
        # Remove single line comments
        code = re.sub(r'//.*?$', '', contract_code, flags=re.MULTILINE)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

        # Don't normalize whitespace - keep line breaks for accurate line numbers
        # code = re.sub(r'\s+', ' ', code)

        return code

    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score"""
        for (min_score, max_score), risk_level in self.risk_levels.items():
            if min_score <= score <= max_score:
                return risk_level
        return "UNKNOWN"

    def analyze(self, contract_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
        """
        Analyze contract code for scam patterns

        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract

        Returns:
            Analysis report with all STE results
        """
        start_time = time.time()

        # Calculate code hash for identification
        code_hash = hashlib.sha256(contract_code.encode('utf-8')).hexdigest()

        # Preprocess code
        preprocessed_code = self._preprocess_code(contract_code)

        # Run all analyzers
        results = []
        total_risk_score = 0
        max_individual_score = 0

        for analyzer in self.analyzers:
            try:
                result = analyzer.analyze(preprocessed_code)
                results.append(result)

                # Track scores
                score = result.get("score", 0)
                total_risk_score += score
                max_individual_score = max(max_individual_score, score)

            except Exception as e:
                results.append({
                    "ste_id": getattr(analyzer, 'ste_id', 'UNKNOWN'),
                    "name": getattr(analyzer, 'name', 'Unknown'),
                    "error": str(e),
                    "score": 0,
                    "matches": []
                })

        # Calculate overall risk score (average of all STE scores)
        avg_score = total_risk_score / len(self.analyzers) if self.analyzers else 0

        # Use weighted approach: 60% max score + 40% average score
        overall_score = (max_individual_score * 0.6) + (avg_score * 0.4)

        # Determine overall risk level
        overall_risk = self._get_risk_level(overall_score)

        # Calculate execution time
        execution_time = time.time() - start_time

        # Build report
        report = {
            "contract_name": contract_name,
            "code_hash": code_hash,
            "analysis_timestamp": time.time(),
            "execution_time": execution_time,
            "overall_score": round(overall_score, 2),
            "overall_risk": overall_risk,
            "max_individual_score": round(max_individual_score, 2),
            "average_score": round(avg_score, 2),
            "ste_results": results,
            "summary": {
                "total_patterns_detected": sum(len(r.get("matches", [])) for r in results),
                "critical_findings": [r for r in results if r.get("score", 0) >= 80],
                "high_risk_findings": [r for r in results if 60 <= r.get("score", 0) < 80],
                "medium_risk_findings": [r for r in results if 40 <= r.get("score", 0) < 60]
            }
        }

        return report

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze contract from file

        Args:
            file_path: Path to Solidity file

        Returns:
            Analysis report
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            contract_code = f.read()

        contract_name = Path(file_path).stem
        return self.analyze(contract_code, contract_name)

    def print_report(self, report: Dict[str, Any]) -> None:
        """Print analysis report in readable format"""
        print("=" * 80)
        print(f"CONTRACT CODE ANALYSIS REPORT")
        print("=" * 80)
        print(f"Contract Name: {report['contract_name']}")
        print(f"Code Hash: {report['code_hash'][:16]}...")
        print(f"Execution Time: {report['execution_time']:.3f}s")
        print()
        print(f"OVERALL RISK: {report['overall_risk']} (Score: {report['overall_score']}/100)")
        print(f"Max Individual Score: {report['max_individual_score']}/100")
        print(f"Average Score: {report['average_score']}/100")
        print()
        print("-" * 80)
        print("STE ANALYSIS RESULTS:")
        print("-" * 80)

        for ste_result in report['ste_results']:
            ste_id = ste_result.get('ste_id', 'N/A')
            name = ste_result.get('name', 'N/A')
            score = ste_result.get('score', 0)
            matches = ste_result.get('matches', [])
            error = ste_result.get('error')

            risk = self._get_risk_level(score)

            print(f"\n{ste_id}: {name}")
            print(f"  Score: {score}/100 ({risk})")

            if error:
                print(f"  ERROR: {error}")
            elif matches:
                print(f"  Patterns Detected: {len(matches)}")
                for match in matches[:3]:  # Show first 3 matches
                    print(f"    - {match.get('description', 'N/A')}")
                    print(f"      Line {match.get('line_number', '?')}: {match.get('matched_text', '')[:60]}...")

                if len(matches) > 3:
                    print(f"    ... and {len(matches) - 3} more")
            else:
                print(f"  No patterns detected")

        print()
        print("-" * 80)
        print("SUMMARY:")
        print("-" * 80)
        print(f"Total Patterns Detected: {report['summary']['total_patterns_detected']}")
        print(f"Critical Findings: {len(report['summary']['critical_findings'])}")
        print(f"High Risk Findings: {len(report['summary']['high_risk_findings'])}")
        print(f"Medium Risk Findings: {len(report['summary']['medium_risk_findings'])}")
        print("=" * 80)


if __name__ == "__main__":
    # Example usage
    analyzer = ContractCodeAnalyzer()

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        report = analyzer.analyze_file(file_path)
        analyzer.print_report(report)
    else:
        print("Usage: python contract_code_analyzer.py <contract_file.sol>")
