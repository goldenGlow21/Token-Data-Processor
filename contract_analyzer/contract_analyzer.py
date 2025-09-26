"""
Ethereum Smart Contract Security Analyzer
이더리움 스마트 컨트랙트 보안 분석 도구

이 도구는 Solidity 스마트 컨트랙트 코드에서 다양한 보안 취약점과 악성 패턴을 탐지합니다.
"""

import re
import json
import time
import hashlib
from typing import List, Dict, Any, Optional

from common.types import Finding, AnalysisResult, AnalysisReport, Severity, AnalysisType
from common.interfaces import BaseAnalyzer, BasePattern


class SourceCodePattern(BasePattern):
    """Source code analysis pattern base class"""

    @property
    def name(self) -> str:
        return self.__class__.__name__.replace('Patterns', '').replace('Pattern', '')

    def analyze(self, contract_code: str) -> List[Finding]:
        """Analyze contract code and return findings"""
        return self._analyze_code(contract_code)

    def _analyze_code(self, contract_code: str) -> List[Finding]:
        """Override this method in subclasses"""
        raise NotImplementedError("Subclasses must implement _analyze_code")

    def _extract_function_name(self, contract_code: str, line_number: int) -> Optional[str]:
        """Extract function name for a given line number"""
        lines = contract_code.split('\n')

        for i in range(line_number - 1, -1, -1):
            line = lines[i].strip()
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                return func_match.group(1)
            if re.search(r'\b(constructor|fallback|receive)\b', line):
                constructor_match = re.search(r'\b(constructor|fallback|receive)\b', line)
                return constructor_match.group(1)

        return None


class ContractAnalyzer(BaseAnalyzer):
    """스마트 컨트랙트 보안 분석기 메인 클래스"""

    def __init__(self):
        super().__init__()

    def _register_patterns(self):
        """분석 패턴들을 등록"""
        from .analyzers.honeypot_patterns import HoneypotPatterns
        from .analyzers.minting_patterns import MintingPatterns
        from .analyzers.fee_patterns import FeePatterns
        from .analyzers.access_control_patterns import AccessControlPatterns
        from .analyzers.metamorphic_patterns import MetamorphicPatterns
        from .analyzers.lowlevel_patterns import LowLevelPatterns
        from .analyzers.function_logic_patterns import FunctionLogicPatterns
        from .analyzers.economic_patterns import EconomicPatterns
        from .analyzers.event_patterns import EventPatterns
        from .analyzers.standard_patterns import StandardPatterns
        from .analyzers.gas_patterns import GasPatterns
        from .analyzers.exit_restriction_patterns import ExitRestrictionPatterns

        self.patterns.extend([
            HoneypotPatterns(),
            MintingPatterns(),
            FeePatterns(),
            AccessControlPatterns(),
            MetamorphicPatterns(),
            LowLevelPatterns(),
            FunctionLogicPatterns(),
            EconomicPatterns(),
            EventPatterns(),
            StandardPatterns(),
            GasPatterns(),
            ExitRestrictionPatterns()
        ])

    def analyze(self, contract_code: str, **kwargs) -> AnalysisReport:
        """
        스마트 컨트랙트 코드를 분석하여 보안 이슈를 탐지

        Args:
            contract_code: 분석할 Solidity 컨트랙트 코드
            **kwargs: 추가 매개변수

        Returns:
            분석 리포트
        """
        start_time = time.time()

        # Create hash for the contract code
        contract_hash = hashlib.sha256(contract_code.encode('utf-8')).hexdigest()

        # Extract contract name
        contract_name = self._extract_contract_name(contract_code)

        # Run pattern analyses
        results = []
        for pattern in self.patterns:
            result = self._run_pattern_analysis(pattern, contract_code)
            results.append(result)

        total_time = time.time() - start_time

        return AnalysisReport(
            analysis_type=AnalysisType.SOURCE_CODE,
            target_hash=contract_hash,
            contract_name=contract_name,
            results=results,
            total_execution_time=total_time
        )

    def analyze_contract(self, contract_code: str) -> Dict[str, Any]:
        """Legacy method for backward compatibility"""
        report = self.analyze(contract_code)
        return self._convert_to_legacy_format(report)

    def _convert_to_legacy_format(self, report: AnalysisReport) -> Dict[str, Any]:
        """Convert new report format to legacy format"""
        # Merge duplicate findings for legacy format
        merged_findings = self._merge_duplicate_findings(report.all_findings)

        return {
            "summary": {
                "total_issues": report.total_issues,
                "pattern_counts": report.pattern_counts
            },
            "findings": merged_findings
        }

    def _extract_contract_name(self, contract_code: str) -> str:
        """Extract contract name from source code"""
        contract_match = re.search(r'contract\s+(\w+)', contract_code)
        return contract_match.group(1) if contract_match else "Unknown"

    def _extract_function_name(self, contract_code: str, line_number: int) -> Optional[str]:
        """주어진 라인 번호가 속한 함수명을 추출"""
        lines = contract_code.split('\n')

        # 해당 라인부터 역순으로 탐색하여 함수 선언부 찾기
        for i in range(line_number - 1, -1, -1):
            line = lines[i].strip()
            # function 키워드로 시작하는 라인 찾기
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                return func_match.group(1)
            # constructor나 fallback, receive 함수
            if re.search(r'\b(constructor|fallback|receive)\b', line):
                constructor_match = re.search(r'\b(constructor|fallback|receive)\b', line)
                return constructor_match.group(1)

        return None

    def _merge_duplicate_findings(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """같은 함수 내 동일 패턴의 중복 탐지를 합치기"""
        # 중복 제거를 위한 딕셔너리 (key: pattern_name + function_name)
        merged_findings = {}

        for finding in findings:
            # 함수명이 없는 경우 라인 번호로 구분
            key = f"{finding.pattern_name}:{finding.function_name or f'line_{finding.line_number}'}"

            if key in merged_findings:
                # 기존 항목에 occurrence 추가
                merged_findings[key]['occurrences'].append({
                    "line_number": finding.line_number,
                    "code_snippet": finding.code_snippet
                })
            else:
                # 새로운 항목 생성
                merged_findings[key] = {
                    "pattern_name": finding.pattern_name,
                    "description": finding.description,
                    "function_name": finding.function_name,
                    "occurrences": [{
                        "line_number": finding.line_number,
                        "code_snippet": finding.code_snippet
                    }]
                }

        return list(merged_findings.values())

    def _generate_report(self, findings: List[Finding], contract_code: str) -> Dict[str, Any]:
        """분석 결과 리포트 생성"""
        # 중복 제거 및 합치기
        merged_findings = self._merge_duplicate_findings(findings)

        pattern_counts = {}

        for finding in merged_findings:
            # 탐지 항목별 건수 카운트 (occurrence 개수 기준)
            pattern_name = finding['pattern_name']
            occurrence_count = len(finding['occurrences'])
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + occurrence_count

        total_issues = sum(len(finding['occurrences']) for finding in merged_findings)

        return {
            "summary": {
                "total_issues": total_issues,
                "pattern_counts": pattern_counts
            },
            "findings": merged_findings
        }

    def analyze_from_file(self, file_path: str) -> Dict[str, Any]:
        """파일에서 컨트랙트 코드를 읽어와 분석"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                contract_code = file.read()
            return self.analyze_contract(contract_code)
        except FileNotFoundError:
            raise FileNotFoundError(f"Contract file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading contract file: {e}")


# Legacy compatibility - export the old class names
AnalysisPattern = SourceCodePattern

# Create a legacy Finding class for backward compatibility with existing patterns
class LegacyFinding:
    """Legacy Finding class for backward compatibility"""
    def __init__(self, pattern_name: str, description: str, code_snippet: str,
                 line_number: Optional[int] = None, function_name: Optional[str] = None,
                 recommendation: str = ""):
        self.pattern_name = pattern_name
        self.description = description
        self.code_snippet = code_snippet
        self.line_number = line_number
        self.function_name = function_name
        self.recommendation = recommendation

# For backward compatibility with existing patterns
Finding = LegacyFinding


def main():
    """메인 실행 함수"""
    import argparse

    parser = argparse.ArgumentParser(description='Ethereum Smart Contract Security Analyzer')
    parser.add_argument('contract_file', help='Path to the Solidity contract file')
    parser.add_argument('--output', '-o', help='Output file for analysis results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    analyzer = ContractAnalyzer()

    try:
        result = analyzer.analyze_from_file(args.contract_file)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"Analysis results saved to {args.output}")
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()