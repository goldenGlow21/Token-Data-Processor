"""
Ethereum Bytecode Security Analyzer
바이트코드 보안 분석 도구

바이트코드를 분석하여 보안 취약점과 악성 패턴을 탐지합니다.
"""

import re
import json
import time
import hashlib
from typing import List, Dict, Any, Optional

from common.types import Finding, AnalysisResult, AnalysisReport, Severity, AnalysisType
from common.interfaces import BaseAnalyzer, BasePattern
from .bytecode_decompiler import BytecodeDecompiler


class BytecodePattern(BasePattern):
    """Bytecode analysis pattern base class"""

    @property
    def name(self) -> str:
        return self.__class__.__name__.replace('Pattern', '').replace('Patterns', '')

    def analyze(self, target: Dict[str, Any]) -> List[Finding]:
        """Analyze bytecode structure and return findings"""
        return self._analyze_bytecode(target)

    def _analyze_bytecode(self, target: Dict[str, Any]) -> List[Finding]:
        """Override this method in subclasses"""
        raise NotImplementedError("Subclasses must implement _analyze_bytecode")


class BytecodeAnalyzer(BaseAnalyzer):
    """바이트코드 보안 분석기 메인 클래스"""

    def __init__(self, signatures_dir: str = "signatures"):
        self.decompiler = BytecodeDecompiler(signatures_dir)
        super().__init__()

    @property
    def malicious_patterns(self) -> Dict[str, Dict]:
        """악성 패턴 정의"""
        return {
            # 직접적인 잔액 조작 패턴
            'balance_manipulation': {
                'selectors': ['70a08231'],  # balanceOf(address)
                'description': 'Balance manipulation detected in bytecode',
                'severity': 'high'
            },

            # 전송 제한 패턴
            'transfer_restriction': {
                'selectors': ['a9059cbb', 'dd62ed3e'],  # transfer, allowance
                'description': 'Transfer restriction mechanisms detected',
                'severity': 'medium'
            },

            # 수수료 조작 패턴
            'fee_manipulation': {
                'selectors': ['313ce567', 'a9059cbb'],  # decimals, transfer
                'description': 'Asymmetric fee structure detected',
                'severity': 'high'
            },

            # 민팅 관련 패턴
            'unlimited_minting': {
                'selectors': ['40c10f19', '18160ddd'],  # mint, totalSupply
                'description': 'Unlimited minting capability detected',
                'severity': 'medium'
            },

            # 일시정지 남용 패턴
            'pause_abuse': {
                'selectors': ['8456cb59', '5c975abb'],  # pause, paused
                'description': 'Contract pause functionality that could block user operations',
                'severity': 'medium'
            },

            # 권한 남용 패턴
            'admin_abuse': {
                'selectors': ['8da5cb5b', 'f2fde38b'],  # owner, transferOwnership
                'description': 'Administrative functions with potential for abuse',
                'severity': 'low'
            }
        }

    def _analyze_function_patterns_as_result(self, target: Dict[str, Any]) -> AnalysisResult:
        """함수 패턴을 분석하여 AnalysisResult 반환"""
        start_time = time.time()

        try:
            functions = target['structure'].get('functions', [])
            findings = []

            # 함수별 선택자 수집
            selectors = [func['selector'] for func in functions]

            for pattern_name, pattern_info in self.malicious_patterns.items():
                pattern_selectors = pattern_info['selectors']

                # 패턴에 해당하는 선택자들이 있는지 확인
                found_selectors = []
                for selector in pattern_selectors:
                    if selector in selectors:
                        found_selectors.append(selector)

                if found_selectors:
                    # 해당 함수 정보 찾기
                    related_functions = [f for f in functions if f['selector'] in found_selectors]

                    for func in related_functions:
                        severity = Severity.HIGH if pattern_info['severity'] == 'high' else \
                                  Severity.MEDIUM if pattern_info['severity'] == 'medium' else \
                                  Severity.LOW

                        finding = Finding(
                            pattern_name=pattern_name.replace('_', ' ').title(),
                            description=pattern_info['description'],
                            severity=severity,
                            selector=f"0x{func['selector']}",
                            function_name=func['name'],
                            recommendation=self._get_recommendation(pattern_name)
                        )
                        findings.append(finding)

            execution_time = time.time() - start_time

            return AnalysisResult(
                pattern_name="Function Pattern Analysis",
                findings=findings,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return AnalysisResult(
                pattern_name="Function Pattern Analysis",
                findings=[],
                execution_time=execution_time,
                error=str(e)
            )

    def _analyze_bytecode_structure_as_result(self, target: Dict[str, Any]) -> AnalysisResult:
        """바이트코드 구조를 직접 분석하여 AnalysisResult 반환"""
        start_time = time.time()

        try:
            bytecode = target['bytecode']
            findings = []
            bytecode_clean = bytecode.replace('0x', '').lower()

            # SELFDESTRUCT (ff) 명령어 탐지
            if 'ff' in bytecode_clean:
                findings.append(Finding(
                    pattern_name="Self Destruct",
                    description="Contract contains self-destruct functionality",
                    severity=Severity.HIGH,
                    selector="0xff",
                    recommendation="Verify if self-destruct is necessary and properly protected"
                ))

            # DELEGATECALL (f4) 명령어 탐지
            if 'f4' in bytecode_clean:
                findings.append(Finding(
                    pattern_name="Delegate Call",
                    description="Contract uses delegatecall which can be dangerous",
                    severity=Severity.MEDIUM,
                    selector="0xf4",
                    recommendation="Ensure delegatecall targets are trusted and validated"
                ))

            # CREATE2 (f5) 명령어 탐지 (메타모르픽 컨트랙트)
            if 'f5' in bytecode_clean:
                findings.append(Finding(
                    pattern_name="Metamorphic Contract",
                    description="Contract uses CREATE2 suggesting metamorphic capabilities",
                    severity=Severity.HIGH,
                    selector="0xf5",
                    recommendation="Verify contract immutability and upgrade mechanisms"
                ))

            execution_time = time.time() - start_time

            return AnalysisResult(
                pattern_name="Bytecode Structure Analysis",
                findings=findings,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return AnalysisResult(
                pattern_name="Bytecode Structure Analysis",
                findings=[],
                execution_time=execution_time,
                error=str(e)
            )

    def _get_recommendation(self, pattern_name: str) -> str:
        """패턴에 따른 권장사항 반환"""
        recommendations = {
            'balance_manipulation': "Avoid contracts that can arbitrarily modify user balances",
            'transfer_restriction': "Check if transfer restrictions are documented and reasonable",
            'fee_manipulation': "Verify fee structures are symmetric and clearly disclosed",
            'unlimited_minting': "Ensure minting is properly controlled and documented",
            'pause_abuse': "Verify pause functionality cannot be used to trap user funds",
            'admin_abuse': "Check if administrative privileges are reasonable and time-locked"
        }
        return recommendations.get(pattern_name, "Review this pattern carefully")

    def _register_patterns(self) -> None:
        """Register bytecode analysis patterns"""
        # For now, we'll use the built-in patterns
        # In the future, these can be extracted to separate pattern classes
        pass

    def analyze(self, bytecode: str, **kwargs) -> AnalysisReport:
        """
        바이트코드를 분석하여 보안 이슈를 탐지

        Args:
            bytecode: 분석할 바이트코드 (hex string)
            **kwargs: 추가 매개변수

        Returns:
            분석 리포트
        """
        start_time = time.time()

        # Create hash for the bytecode
        bytecode_hash = hashlib.sha256(bytecode.encode('utf-8')).hexdigest()

        try:
            # 바이트코드 구조 분석
            structure = self.decompiler.analyze_bytecode_structure(bytecode)

            # Extract contract name (if available)
            contract_name = kwargs.get('contract_name', 'Unknown')

            # Create analysis target
            analysis_target = {
                'bytecode': bytecode,
                'structure': structure
            }

            # Run pattern analyses
            results = []

            # Built-in function pattern analysis
            function_result = self._analyze_function_patterns_as_result(analysis_target)
            if function_result.findings:
                results.append(function_result)

            # Built-in bytecode structure analysis
            structure_result = self._analyze_bytecode_structure_as_result(analysis_target)
            if structure_result.findings:
                results.append(structure_result)

        except Exception as e:
            # Create error result
            results = [AnalysisResult(
                pattern_name="Bytecode Analysis Error",
                findings=[],
                error=str(e)
            )]
            structure = {}

        total_time = time.time() - start_time

        return AnalysisReport(
            analysis_type=AnalysisType.BYTECODE,
            target_hash=bytecode_hash,
            contract_name=contract_name,
            results=results,
            total_execution_time=total_time,
            metadata={'structure': structure}
        )

    def analyze_bytecode(self, bytecode: str) -> Dict[str, Any]:
        """Legacy method for backward compatibility"""
        report = self.analyze(bytecode)
        return self._convert_to_legacy_format(report)

    def _convert_to_legacy_format(self, report: AnalysisReport) -> Dict[str, Any]:
        """Convert new report format to legacy format"""
        structure = report.metadata.get('structure', {})

        # Convert findings to legacy format
        merged_findings = []
        finding_dict = {}

        for finding in report.all_findings:
            key = f"{finding.pattern_name}:{finding.function_name or finding.selector}"

            if key in finding_dict:
                finding_dict[key]['occurrences'].append({
                    "selector": finding.selector,
                    "function_name": finding.function_name
                })
            else:
                finding_dict[key] = {
                    "pattern_name": finding.pattern_name,
                    "description": finding.description,
                    "function_name": finding.function_name,
                    "recommendation": finding.recommendation,
                    "occurrences": [{
                        "selector": finding.selector,
                        "function_name": finding.function_name
                    }]
                }

        merged_findings = list(finding_dict.values())

        return {
            "summary": {
                "total_issues": report.total_issues,
                "pattern_counts": report.pattern_counts,
                "total_functions": len(structure.get('functions', [])),
                "analysis_type": "bytecode"
            },
            "findings": merged_findings,
            "contract_info": {
                "functions": structure.get('functions', []),
                "events": structure.get('events', []),
                "has_constructor": structure.get('constructor') is not None
            }
        }

    def _generate_report(self, findings: List[BytecodeFinding], structure: Dict) -> Dict[str, Any]:
        """분석 결과 리포트 생성"""
        # 패턴별 카운트
        pattern_counts = {}
        merged_findings = []

        # 중복 제거를 위한 딕셔너리
        finding_dict = {}

        for finding in findings:
            key = f"{finding.pattern_name}:{finding.function_name or finding.selector}"

            if key in finding_dict:
                # 이미 존재하는 경우 occurrences 추가
                finding_dict[key]['occurrences'].append({
                    "selector": finding.selector,
                    "function_name": finding.function_name
                })
            else:
                # 새로운 항목 생성
                finding_dict[key] = {
                    "pattern_name": finding.pattern_name,
                    "description": finding.description,
                    "function_name": finding.function_name,
                    "recommendation": finding.recommendation,
                    "occurrences": [{
                        "selector": finding.selector,
                        "function_name": finding.function_name
                    }]
                }

        merged_findings = list(finding_dict.values())

        # 패턴 카운트 계산
        for finding in merged_findings:
            pattern_name = finding['pattern_name']
            occurrence_count = len(finding['occurrences'])
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + occurrence_count

        total_issues = sum(len(finding['occurrences']) for finding in merged_findings)

        return {
            "summary": {
                "total_issues": total_issues,
                "pattern_counts": pattern_counts,
                "total_functions": len(structure.get('functions', [])),
                "analysis_type": "bytecode"
            },
            "findings": merged_findings,
            "contract_info": {
                "functions": structure.get('functions', []),
                "events": structure.get('events', []),
                "has_constructor": structure.get('constructor') is not None
            }
        }

    def analyze_from_file(self, bytecode_file: str) -> Dict[str, Any]:
        """파일에서 바이트코드를 읽어와 분석"""
        try:
            with open(bytecode_file, 'r', encoding='utf-8') as f:
                bytecode = f.read().strip()
            return self.analyze_bytecode(bytecode)
        except FileNotFoundError:
            raise FileNotFoundError(f"Bytecode file not found: {bytecode_file}")
        except Exception as e:
            raise Exception(f"Error reading bytecode file: {e}")


def main():
    """메인 실행 함수"""
    import argparse

    parser = argparse.ArgumentParser(description='Ethereum Bytecode Security Analyzer')
    parser.add_argument('bytecode_file', help='Path to the bytecode file')
    parser.add_argument('--output', '-o', help='Output file for analysis results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    analyzer = BytecodeAnalyzer()

    try:
        result = analyzer.analyze_from_file(args.bytecode_file)

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