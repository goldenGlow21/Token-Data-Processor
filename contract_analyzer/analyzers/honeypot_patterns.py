"""
허니팟 패턴 탐지 모듈
전송/판매 제한 및 조건부 제한 로직을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class HoneypotPatterns(AnalysisPattern):
    """허니팟 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        # 블랙리스트 시스템 탐지
        findings.extend(self._detect_blacklist_system(contract_code))
        # 화이트리스트 전용 시스템 탐지
        findings.extend(self._detect_whitelist_only(contract_code))
        # 판매 함수 비활성화 탐지
        findings.extend(self._detect_disabled_selling(contract_code))
        # 조건부 제한 로직 탐지
        findings.extend(self._detect_conditional_restrictions(contract_code))
        # 시간 기반 잠금 탐지
        findings.extend(self._detect_time_locks(contract_code))
        # 최소 판매량 제한 탐지
        findings.extend(self._detect_unrealistic_min_sell(contract_code))
        return findings
    def _detect_blacklist_system(self, code: str) -> List[Finding]:
        findings = []
        # 블랙리스트 매핑 패턴
        blacklist_patterns = [
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Bb]lacklist\w*',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Bb]anned?\w*',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Bb]locked?\w*'
        ]
        for pattern in blacklist_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # transfer 함수에서 블랙리스트 체크하는지 확인
                if self._check_blacklist_in_transfer(code, match.group()):
                    findings.append(Finding(
                        pattern_name="Blacklist System",
                        description="블랙리스트 시스템이 구현되어 특정 주소의 토큰 전송을 차단할 수 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _check_blacklist_in_transfer(self, code: str, blacklist_var: str) -> bool:
        """transfer 함수에서 블랙리스트를 체크하는지 확인"""
        # 변수명 추출
        var_name = re.search(r'\w+$', blacklist_var.split()[-1])
        if not var_name:
            return False
        var_name = var_name.group()
        # transfer 함수 찾기
        transfer_pattern = r'function\s+transfer\s*\([^}]*\{[^}]*\}'
        transfer_matches = re.finditer(transfer_pattern, code, re.DOTALL)
        for transfer_match in transfer_matches:
            transfer_body = transfer_match.group()
            if re.search(rf'{var_name}\s*\[', transfer_body):
                return True
        return False
    def _detect_whitelist_only(self, code: str) -> List[Finding]:
        findings = []
        # 화이트리스트 매핑 패턴
        whitelist_patterns = [
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Ww]hitelist\w*',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Aa]llowed?\w*',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*\w*[Aa]uthorized?\w*'
        ]
        for pattern in whitelist_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # transfer에서 화이트리스트 전용인지 확인
                if self._check_whitelist_only_transfer(code, match.group()):
                    findings.append(Finding(
                        pattern_name="Whitelist Only System",
                        description="화이트리스트에 없는 주소는 토큰을 전송할 수 없는 시스템입니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _check_whitelist_only_transfer(self, code: str, whitelist_var: str) -> bool:
        """transfer가 화이트리스트 전용인지 확인"""
        var_name = re.search(r'\w+$', whitelist_var.split()[-1])
        if not var_name:
            return False
        var_name = var_name.group()
        # require(!whitelist[...]) 패턴 찾기
        require_patterns = [
            rf'require\s*\(\s*{var_name}\s*\[.*?\]\s*\)',
            rf'require\s*\(\s*!{var_name}\s*\[.*?\]\s*\)'
        ]
        for pattern in require_patterns:
            if re.search(pattern, code):
                return True
        return False
    def _detect_disabled_selling(self, code: str) -> List[Finding]:
        findings = []
        # transfer 함수에서 항상 실패하는 패턴들
        disabled_patterns = [
            r'require\s*\(\s*false\s*\)',
            r'require\s*\(\s*1\s*==\s*2\s*\)',
            r'require\s*\(\s*0\s*==\s*1\s*\)',
            r'revert\s*\(\s*["\'].*?["\']\s*\)',
            r'if\s*\(\s*true\s*\)\s*\{\s*revert'
        ]
        # transfer 함수 찾기
        transfer_pattern = r'function\s+transfer\s*\([^}]*\{[^}]*\}'
        transfer_matches = re.finditer(transfer_pattern, code, re.DOTALL)
        for transfer_match in transfer_matches:
            transfer_body = transfer_match.group()
            for pattern in disabled_patterns:
                if re.search(pattern, transfer_body):
                    line_num = code[:transfer_match.start()].count('\n') + 1
                    findings.append(Finding(
                        pattern_name="Disabled Transfer Function",
                        description="transfer 함수가 항상 실패하도록 구현되어 있습니다.",
                        code_snippet=transfer_body[:200] + "...",
                        line_number=line_num
                    ))
                    break
        return findings
    def _detect_conditional_restrictions(self, code: str) -> List[Finding]:
        findings = []
        # owner만 판매 가능한 패턴
        owner_only_patterns = [
            r'require\s*\(\s*msg\.sender\s*==\s*owner\s*\)',
            r'require\s*\(\s*_msgSender\(\)\s*==\s*owner\s*\)',
            r'onlyOwner\s+modifier'
        ]
        # transfer 함수에서 owner 체크
        transfer_pattern = r'function\s+transfer\s*\([^}]*\{[^}]*\}'
        transfer_matches = re.finditer(transfer_pattern, code, re.DOTALL)
        for transfer_match in transfer_matches:
            transfer_body = transfer_match.group()
            for pattern in owner_only_patterns:
                if re.search(pattern, transfer_body):
                    line_num = code[:transfer_match.start()].count('\n') + 1
                    findings.append(Finding(
                        pattern_name="Owner-Only Transfer",
                        description="owner만 토큰을 전송할 수 있도록 제한되어 있습니다.",
                        code_snippet=transfer_body[:200] + "...",
                        line_number=line_num
                    ))
                    break
        return findings
    def _detect_time_locks(self, code: str) -> List[Finding]:
        findings = []
        # 시간 기반 잠금 패턴
        time_lock_patterns = [
            r'require\s*\(\s*block\.timestamp\s*[><=]+\s*\w+',
            r'require\s*\(\s*now\s*[><=]+\s*\w+',
            r'require\s*\(\s*block\.number\s*[><=]+\s*\w+'
        ]
        for pattern in time_lock_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Time-based Lock",
                    description="시간 또는 블록 번호 기반의 잠금 메커니즘이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_unrealistic_min_sell(self, code: str) -> List[Finding]:
        findings = []
        # 비현실적인 최소 판매량 패턴 (1억 토큰 이상)
        min_sell_patterns = [
            r'require\s*\(\s*amount\s*>=\s*\d{8,}',  # 1억 이상
            r'minSellAmount\s*=\s*\d{8,}',
            r'require\s*\(\s*_amount\s*>=\s*\d{8,}'
        ]
        for pattern in min_sell_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # 숫자 추출하여 실제로 큰 값인지 확인
                numbers = re.findall(r'\d+', match.group())
                for num in numbers:
                    if int(num) >= 100000000:  # 1억 이상
                        line_num = code[:match.start()].count('\n') + 1
                        findings.append(Finding(
                            pattern_name="Unrealistic Minimum Sell Amount",
                                description=f"비현실적으로 큰 최소 판매량이 설정되어 있습니다: {num}",
                            code_snippet=match.group(),
                            line_number=line_num
                        ))
                        break
        return findings