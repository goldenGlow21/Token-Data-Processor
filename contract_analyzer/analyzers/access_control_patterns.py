"""
접근 제어 권한 남용 탐지 모듈
과도한 Owner 권한 및 권한 체계 문제를 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class AccessControlPatterns(AnalysisPattern):
    """접근 제어 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_excessive_owner_powers(contract_code))
        findings.extend(self._detect_balance_manipulation(contract_code))
        findings.extend(self._detect_emergency_withdrawal(contract_code))
        findings.extend(self._detect_contract_pause_abuse(contract_code))
        findings.extend(self._detect_broken_renounce_ownership(contract_code))
        return findings
    def _detect_excessive_owner_powers(self, code: str) -> List[Finding]:
        findings = []
        excessive_patterns = [
            (r'function\s+\w*[Ss]eize\w*.*onlyOwner', "토큰 압수 기능"),
            (r'function\s+\w*[Ff]reeze\w*.*onlyOwner', "계정 동결 기능"),
            (r'function\s+\w*[Bb]lock\w*.*onlyOwner', "계정 차단 기능"),
            (r'function\s+\w*[Bb]an\w*.*onlyOwner', "계정 밴 기능")
        ]
        for pattern, description in excessive_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Excessive Owner Powers",
                    description=f"Owner가 {description}을 가지고 있습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_balance_manipulation(self, code: str) -> List[Finding]:
        findings = []
        balance_manip_patterns = [
            r'function\s+\w*.*onlyOwner.*balanceOf\s*\[\s*\w+\s*\]\s*=',
            r'function\s+\w*.*onlyOwner.*_balances\s*\[\s*\w+\s*\]\s*=',
            r'onlyOwner.*balanceOf\s*\[\s*\w+\s*\]\s*=\s*0'
        ]
        for pattern in balance_manip_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Balance Manipulation",
                    description="Owner가 사용자의 잔액을 임의로 조작할 수 있습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_emergency_withdrawal(self, code: str) -> List[Finding]:
        findings = []
        emergency_patterns = [
            r'function\s+\w*[Ee]mergency\w*.*onlyOwner',
            r'function\s+\w*[Ww]ithdraw\w*.*onlyOwner.*address\(this\)\.balance',
            r'function\s+\w*[Rr]escue\w*.*onlyOwner'
        ]
        for pattern in emergency_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Emergency Withdrawal",
                    description="Owner가 컨트랙트의 모든 자금을 인출할 수 있습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_contract_pause_abuse(self, code: str) -> List[Finding]:
        findings = []
        pause_patterns = [
            r'function\s+pause\s*\(\s*\).*onlyOwner',
            r'function\s+\w*[Pp]ause\w*.*onlyOwner',
            r'paused\s*=\s*true'
        ]
        for pattern in pause_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Contract Pause Abuse",
                    description="Owner가 컨트랙트를 일시정지시켜 모든 거래를 차단할 수 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_broken_renounce_ownership(self, code: str) -> List[Finding]:
        findings = []
        # renounceOwnership 함수가 있는지 확인
        renounce_pattern = r'function\s+renounceOwnership\s*\([^}]*\{[^}]*\}'
        matches = re.finditer(renounce_pattern, code, re.DOTALL)
        for match in matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # 실제로 owner를 제거하는지 확인
            removes_owner = any([
                re.search(r'owner\s*=\s*address\(0\)', function_body),
                re.search(r'_owner\s*=\s*address\(0\)', function_body),
                re.search(r'delete\s+owner', function_body)
            ])
            if not removes_owner:
                findings.append(Finding(
                    pattern_name="Broken Renounce Ownership",
                    description="renounceOwnership 함수가 실제로 소유권을 포기하지 않습니다.",
                    code_snippet=function_body[:200] + "...",
                    line_number=line_num
                ))
        return findings