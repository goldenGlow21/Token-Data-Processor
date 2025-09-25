"""
가스 및 실행 조작 탐지 모듈
가스 트랩 및 실행 흐름 조작을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class GasPatterns(AnalysisPattern):
    """가스 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_infinite_loops(contract_code))
        findings.extend(self._detect_gas_bombs(contract_code))
        findings.extend(self._detect_reentrancy_vulnerabilities(contract_code))
        findings.extend(self._detect_execution_order_dependency(contract_code))
        return findings
    def _detect_infinite_loops(self, code: str) -> List[Finding]:
        findings = []
        # 무한 루프 패턴들
        infinite_patterns = [
            r'while\s*\(\s*true\s*\)',
            r'for\s*\([^;]*;\s*true\s*;[^)]*\)',
            r'while\s*\(\s*1\s*==\s*1\s*\)',
            r'for\s*\([^;]*;\s*1\s*==\s*1\s*;[^)]*\)'
        ]
        for pattern in infinite_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # 루프 내부에 break 조건이 있는지 확인
                loop_start = match.end()
                brace_count = 0
                loop_end = loop_start
                for i, char in enumerate(code[loop_start:]):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            loop_end = loop_start + i + 1
                            break
                loop_body = code[loop_start:loop_end]
                has_break = 'break' in loop_body or 'return' in loop_body
                if not has_break:
                    findings.append(Finding(
                        pattern_name="Infinite Loop",
                        description="탈출 조건이 없는 무한 루프가 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_gas_bombs(self, code: str) -> List[Finding]:
        findings = []
        # 가스 폭탄 패턴들
        gas_bomb_patterns = [
            (r'for\s*\([^;]*;\s*i\s*<\s*\d{4,}', '큰 루프 반복'),
            (r'while\s*\([^)]*\s*<\s*\d{4,}', '큰 while 루프'),
            (r'new\s+\w+\[\]\s*\(\s*\d{4,}', '큰 배열 생성'),
            (r'string\s*\(\s*new\s+bytes\s*\(\s*\d{4,}', '큰 문자열 생성')
        ]
        for pattern, description in gas_bomb_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # 숫자 추출
                numbers = re.findall(r'\d+', match.group())
                for num in numbers:
                    if int(num) >= 1000:
                        findings.append(Finding(
                            pattern_name="Gas Bomb",
                                description=f"높은 가스 소모를 유발할 수 있는 패턴: {description} ({num})",
                            code_snippet=match.group(),
                            line_number=line_num
                        ))
                        break
        return findings
    def _detect_reentrancy_vulnerabilities(self, code: str) -> List[Finding]:
        findings = []
        # 재진입 공격 가능한 패턴들
        # external call 후에 상태 변경이 있는 패턴
        external_call_patterns = [
            r'\.call\s*\(',
            r'\.transfer\s*\(',
            r'\.send\s*\(',
            r'\.delegatecall\s*\('
        ]
        for pattern in external_call_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # external call 이후에 상태 변경이 있는지 확인
                after_call = code[match.end():match.end()+500]
                has_state_change = any([
                    re.search(r'balanceOf\s*\[\s*\w+\s*\]\s*[+\-=]', after_call),
                    re.search(r'_balances\s*\[\s*\w+\s*\]\s*[+\-=]', after_call),
                    re.search(r'\w+\s*=\s*\w+', after_call)
                ])
                if has_state_change:
                    findings.append(Finding(
                        pattern_name="Reentrancy Vulnerability",
                        description="외부 호출 후 상태 변경으로 재진입 공격에 취약할 수 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_execution_order_dependency(self, code: str) -> List[Finding]:
        findings = []
        # 실행 순서 의존성 패턴들
        order_patterns = [
            (r'block\.timestamp', '타임스탬프 의존성'),
            (r'block\.number', '블록 번호 의존성'),
            (r'tx\.gasprice', '가스 가격 의존성'),
            (r'tx\.origin', 'tx.origin 사용')
        ]
        for pattern, description in order_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # 이것이 중요한 비즈니스 로직에 사용되는지 확인
                context = code[max(0, match.start()-100):match.end()+100]
                in_important_logic = any([
                    'require(' in context,
                    'if (' in context,
                    'return' in context,
                    '=' in context
                ])
                if in_important_logic:
                    findings.append(Finding(
                        pattern_name="Execution Order Dependency",
                        description=f"실행 순서나 환경에 의존하는 로직: {description}",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings