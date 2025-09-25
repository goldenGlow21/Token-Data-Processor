"""
이벤트 및 로깅 조작 탐지 모듈
거짓 이벤트 및 로그 위조를 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class EventPatterns(AnalysisPattern):
    """이벤트 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_misleading_events(contract_code))
        findings.extend(self._detect_missing_events(contract_code))
        findings.extend(self._detect_fake_success_events(contract_code))
        return findings
    def _detect_misleading_events(self, code: str) -> List[Finding]:
        findings = []
        # 이벤트 정의 찾기
        event_pattern = r'event\s+(\w+)\s*\([^)]*\);'
        events = re.findall(event_pattern, code)
        # emit 패턴 찾기
        emit_pattern = r'emit\s+(\w+)\s*\([^)]*\);'
        emit_matches = re.finditer(emit_pattern, code)
        for emit_match in emit_matches:
            event_name = emit_match.group(1)
            line_num = code[:emit_match.start()].count('\n') + 1
            # Transfer 이벤트인 경우 실제 잔액 변경이 있는지 확인
            if event_name == 'Transfer':
                # 주변 코드에서 실제 잔액 변경이 있는지 확인
                context = code[max(0, emit_match.start()-300):emit_match.end()+100]
                has_balance_change = any([
                    re.search(r'balanceOf\s*\[\s*\w+\s*\]\s*[+\-]=', context),
                    re.search(r'_balances\s*\[\s*\w+\s*\]\s*[+\-]=', context),
                    re.search(r'_transfer\s*\(', context)
                ])
                if not has_balance_change:
                    findings.append(Finding(
                        pattern_name="Misleading Transfer Event",
                        description="Transfer 이벤트가 발생하지만 실제 잔액 변경이 없습니다.",
                        code_snippet=emit_match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_missing_events(self, code: str) -> List[Finding]:
        findings = []
        # 중요한 상태 변경 함수들에서 이벤트가 누락되었는지 확인
        important_functions = [
            (r'function\s+mint\s*\([^}]*\{[^}]*\}', 'Mint'),
            (r'function\s+burn\s*\([^}]*\{[^}]*\}', 'Burn'),
            (r'function\s+transferOwnership\s*\([^}]*\{[^}]*\}', 'OwnershipTransferred')
        ]
        for func_pattern, expected_event in important_functions:
            func_matches = re.finditer(func_pattern, code, re.DOTALL)
            for func_match in func_matches:
                function_body = func_match.group()
                line_num = code[:func_match.start()].count('\n') + 1
                # 해당 이벤트가 함수 내에서 발생하는지 확인
                has_event = re.search(rf'emit\s+{expected_event}', function_body)
                if not has_event:
                    findings.append(Finding(
                        pattern_name="Missing Event",
                        description=f"중요한 상태 변경에 대한 {expected_event} 이벤트가 누락되었습니다.",
                        code_snippet=function_body[:200] + "...",
                        line_number=line_num
                    ))
        return findings
    def _detect_fake_success_events(self, code: str) -> List[Finding]:
        findings = []
        # 함수에서 실패했는데도 성공 이벤트를 발생시키는 패턴
        success_events = ['Success', 'Completed', 'Finished', 'Done']
        for event_name in success_events:
            # 해당 이벤트를 찾기
            emit_pattern = rf'emit\s+{event_name}\s*\([^)]*\);'
            emit_matches = re.finditer(emit_pattern, code)
            for emit_match in emit_matches:
                line_num = code[:emit_match.start()].count('\n') + 1
                # 이벤트 앞에 실패 조건이 있는지 확인
                before_emit = code[max(0, emit_match.start()-500):emit_match.start()]
                has_failure = any([
                    re.search(r'require\s*\(\s*false\s*\)', before_emit),
                    re.search(r'revert\s*\(', before_emit),
                    re.search(r'return\s+false', before_emit)
                ])
                if has_failure:
                    findings.append(Finding(
                        pattern_name="Fake Success Event",
                        description=f"실패한 거래에 대해 {event_name} 이벤트가 발생합니다.",
                        code_snippet=emit_match.group(),
                        line_number=line_num
                    ))
        return findings