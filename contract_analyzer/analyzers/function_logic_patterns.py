"""
함수 로직 조작 탐지 모듈
조건문 트랩 및 함수 오버라이드/위장을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class FunctionLogicPatterns(AnalysisPattern):
    """함수 로직 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_impossible_conditions(contract_code))
        findings.extend(self._detect_time_based_traps(contract_code))
        findings.extend(self._detect_address_based_logic(contract_code))
        findings.extend(self._detect_misleading_function_names(contract_code))
        findings.extend(self._detect_dummy_functions(contract_code))
        findings.extend(self._detect_malicious_fallback(contract_code))
        return findings
    def _detect_impossible_conditions(self, code: str) -> List[Finding]:
        findings = []
        impossible_patterns = [
            (r'require\s*\(\s*false\s*\)', '항상 거짓인 require'),
            (r'require\s*\(\s*1\s*==\s*2\s*\)', '불가능한 조건'),
            (r'require\s*\(\s*0\s*==\s*1\s*\)', '불가능한 조건'),
            (r'if\s*\(\s*false\s*\)', '항상 거짓인 조건'),
            (r'if\s*\(\s*1\s*==\s*2\s*\)', '불가능한 조건')
        ]
        for pattern, description in impossible_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Impossible Condition",
                    description=f"{description}이 발견되었습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_time_based_traps(self, code: str) -> List[Finding]:
        findings = []
        time_patterns = [
            r'require\s*\(\s*block\.timestamp\s*==\s*\d+',
            r'require\s*\(\s*block\.number\s*==\s*\d+',
            r'if\s*\(\s*now\s*==\s*\d+'
        ]
        for pattern in time_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Time-based Trap",
                    description="특정 시간이나 블록에서만 작동하는 조건이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_address_based_logic(self, code: str) -> List[Finding]:
        findings = []
        address_patterns = [
            r'require\s*\(\s*msg\.sender\s*==\s*0x[a-fA-F0-9]{40}',
            r'if\s*\(\s*msg\.sender\s*==\s*0x[a-fA-F0-9]{40}',
            r'require\s*\(\s*tx\.origin\s*==\s*0x[a-fA-F0-9]{40}'
        ]
        for pattern in address_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                address = re.search(r'0x[a-fA-F0-9]{40}', match.group())
                findings.append(Finding(
                    pattern_name="Address-based Logic",
                    description=f"특정 주소({address.group()[:10]}...)에서만 다르게 동작합니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_misleading_function_names(self, code: str) -> List[Finding]:
        findings = []
        # 안전해 보이는 이름의 함수들
        safe_names = [
            r'function\s+safeTransfer\s*\(',
            r'function\s+safeMint\s*\(',
            r'function\s+secureWithdraw\s*\(',
            r'function\s+verifiedTransfer\s*\('
        ]
        for pattern in safe_names:
            matches = re.finditer(pattern, code)
            for match in matches:
                # 함수 본문 가져오기
                function_start = match.end()
                brace_count = 0
                function_end = function_start
                for i, char in enumerate(code[function_start:]):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            function_end = function_start + i + 1
                            break
                function_body = code[function_start:function_end]
                line_num = code[:match.start()].count('\n') + 1
                # 의심스러운 패턴들 찾기
                suspicious_patterns = [
                    r'selfdestruct\s*\(',
                    r'suicide\s*\(',
                    r'assembly\s*\{',
                    r'delegatecall\s*\(',
                    r'msg\.sender\.transfer\s*\(\s*address\(this\)\.balance\s*\)'
                ]
                for sus_pattern in suspicious_patterns:
                    if re.search(sus_pattern, function_body):
                        findings.append(Finding(
                            pattern_name="Misleading Function Name",
                                    description="안전해 보이는 함수명에 의심스러운 로직이 있습니다.",
                            code_snippet=match.group()[:100] + "...",
                            line_number=line_num
                        ))
                        break
        return findings
    def _detect_dummy_functions(self, code: str) -> List[Finding]:
        findings = []
        # 빈 함수들이나 아무것도 하지 않는 함수들
        dummy_patterns = [
            r'function\s+\w+\s*\([^)]*\)\s*\w*\s*\{\s*\}',
            r'function\s+\w+\s*\([^)]*\)\s*\w*\s*\{\s*return\s*;\s*\}',
            r'function\s+\w+\s*\([^)]*\)\s*\w*\s*\{\s*\/\/.*\s*\}'
        ]
        for pattern in dummy_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                function_name = re.search(r'function\s+(\w+)', match.group())
                if function_name:
                    # 중요해 보이는 함수명들
                    important_names = ['security', 'verify', 'validate', 'check', 'audit', 'safe']
                    if any(name in function_name.group(1).lower() for name in important_names):
                        findings.append(Finding(
                            pattern_name="Dummy Security Function",
                                    description=f"보안 관련 함수 {function_name.group(1)}가 실제로는 아무것도 하지 않습니다.",
                            code_snippet=match.group(),
                            line_number=line_num
                        ))
        return findings
    def _detect_malicious_fallback(self, code: str) -> List[Finding]:
        findings = []
        fallback_patterns = [
            r'fallback\s*\(\s*\)\s*\w*\s*\{[^}]*\}',
            r'receive\s*\(\s*\)\s*\w*\s*\{[^}]*\}'
        ]
        for pattern in fallback_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                function_body = match.group()
                line_num = code[:match.start()].count('\n') + 1
                # fallback에서 의심스러운 동작들
                suspicious_in_fallback = [
                    r'selfdestruct\s*\(',
                    r'suicide\s*\(',
                    r'assembly\s*\{',
                    r'_mint\s*\(',
                    r'balanceOf\s*\[\s*\w+\s*\]\s*='
                ]
                for sus_pattern in suspicious_in_fallback:
                    if re.search(sus_pattern, function_body):
                        findings.append(Finding(
                            pattern_name="Malicious Fallback Function",
                                    description="fallback/receive 함수에 악성 로직이 있습니다.",
                            code_snippet=function_body[:200] + "...",
                            line_number=line_num
                        ))
                        break
        return findings