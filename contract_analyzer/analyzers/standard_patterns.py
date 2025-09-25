"""
표준 위반 패턴 탐지 모듈
ERC-20 표준 위반 및 기타 표준 위반을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class StandardPatterns(AnalysisPattern):
    """표준 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_erc20_violations(contract_code))
        findings.extend(self._detect_transfer_manipulation(contract_code))
        findings.extend(self._detect_approve_manipulation(contract_code))
        findings.extend(self._detect_balance_inconsistency(contract_code))
        return findings
    def _detect_erc20_violations(self, code: str) -> List[Finding]:
        findings = []
        # ERC-20 필수 함수들이 있는지 확인
        required_functions = [
            'totalSupply',
            'balanceOf',
            'transfer',
            'transferFrom',
            'approve',
            'allowance'
        ]
        missing_functions = []
        for func in required_functions:
            if not re.search(rf'function\s+{func}\s*\(', code):
                missing_functions.append(func)
        if missing_functions:
            findings.append(Finding(
                pattern_name="Missing ERC-20 Functions",
                description=f"ERC-20 필수 함수들이 누락되었습니다: {', '.join(missing_functions)}",
                code_snippet=f"Missing: {missing_functions}",
                line_number=1
            ))
        return findings
    def _detect_transfer_manipulation(self, code: str) -> List[Finding]:
        findings = []
        # transfer 함수 찾기
        transfer_pattern = r'function\s+transfer\s*\([^}]*\{[^}]*\}'
        transfer_matches = re.finditer(transfer_pattern, code, re.DOTALL)
        for match in transfer_matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # transfer가 표준과 다르게 동작하는지 확인
            suspicious_patterns = [
                (r'require\s*\(\s*false\s*\)', '항상 실패'),
                (r'return\s+false', '항상 false 반환'),
                (r'revert\s*\(', '항상 revert'),
                (r'msg\.sender\s*==\s*owner', 'owner만 실행 가능')
            ]
            for pattern, description in suspicious_patterns:
                if re.search(pattern, function_body):
                    findings.append(Finding(
                        pattern_name="Transfer Function Manipulation",
                        description=f"transfer 함수가 표준과 다르게 동작합니다: {description}",
                        code_snippet=function_body[:200] + "...",
                        line_number=line_num
                    ))
                    break
        return findings
    def _detect_approve_manipulation(self, code: str) -> List[Finding]:
        findings = []
        # approve 함수 찾기
        approve_pattern = r'function\s+approve\s*\([^}]*\{[^}]*\}'
        approve_matches = re.finditer(approve_pattern, code, re.DOTALL)
        for match in approve_matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # approve가 실제로 승인을 설정하는지 확인
            sets_allowance = any([
                re.search(r'allowance\s*\[', function_body),
                re.search(r'_allowances\s*\[', function_body),
                re.search(r'_approve\s*\(', function_body)
            ])
            if not sets_allowance:
                findings.append(Finding(
                    pattern_name="Approve Function Manipulation",
                        description="approve 함수가 실제로 승인을 설정하지 않습니다.",
                    code_snippet=function_body[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_balance_inconsistency(self, code: str) -> List[Finding]:
        findings = []
        # balanceOf 함수 찾기
        balance_pattern = r'function\s+balanceOf\s*\([^}]*\{[^}]*\}'
        balance_matches = re.finditer(balance_pattern, code, re.DOTALL)
        for match in balance_matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # balanceOf가 실제 잔액을 반환하는지 확인
            suspicious_patterns = [
                (r'return\s+0', '항상 0 반환'),
                (r'return\s+\d+', '고정값 반환'),
                (r'return\s+totalSupply', 'totalSupply 반환')
            ]
            for pattern, description in suspicious_patterns:
                if re.search(pattern, function_body):
                    findings.append(Finding(
                        pattern_name="Balance Inconsistency",
                        description=f"balanceOf 함수가 의심스러운 값을 반환합니다: {description}",
                        code_snippet=function_body[:200] + "...",
                        line_number=line_num
                    ))
                    break
        return findings