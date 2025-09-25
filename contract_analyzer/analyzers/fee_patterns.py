"""
수수료 및 세금 조작 탐지 모듈
극단적 수수료 및 수수료 흐름 조작을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class FeePatterns(AnalysisPattern):
    """수수료 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        # 극단적 수수료 탐지
        findings.extend(self._detect_extreme_fees(contract_code))
        # 동적 수수료 조작 탐지
        findings.extend(self._detect_dynamic_fee_manipulation(contract_code))
        # 비대칭 수수료 탐지
        findings.extend(self._detect_asymmetric_fees(contract_code))
        # 수수료 상한선 없음 탐지
        findings.extend(self._detect_no_fee_limits(contract_code))
        # 예상외 수수료 수신자 탐지
        findings.extend(self._detect_unexpected_fee_recipient(contract_code))
        # 수수료 계산 오류 탐지
        findings.extend(self._detect_fee_calculation_errors(contract_code))
        # 다중 수수료 탐지
        findings.extend(self._detect_multiple_fees(contract_code))
        return findings
    def _detect_extreme_fees(self, code: str) -> List[Finding]:
        findings = []
        # 극단적 수수료 패턴들 (90% 이상)
        extreme_fee_patterns = [
            r'\w*[Tt]ax\w*\s*=\s*(9[0-9]|100)',
            r'\w*[Ff]ee\w*\s*=\s*(9[0-9]|100)',
            r'sellTax\s*=\s*(9[0-9]|100)',
            r'buyTax\s*=\s*(9[0-9]|100)',
            r'transferTax\s*=\s*(9[0-9]|100)'
        ]
        for pattern in extreme_fee_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                fee_value = re.search(r'\d+', match.group()).group()
                if int(fee_value) >= 90:
                    findings.append(Finding(
                        pattern_name="Extreme Fee Rate",
                        description=f"극단적으로 높은 수수료가 설정되어 있습니다: {fee_value}%",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_dynamic_fee_manipulation(self, code: str) -> List[Finding]:
        findings = []
        # 수수료 설정 함수들
        fee_setter_patterns = [
            r'function\s+set\w*[Tt]ax\w*\s*\([^}]*\{[^}]*\}',
            r'function\s+set\w*[Ff]ee\w*\s*\([^}]*\{[^}]*\}',
            r'function\s+update\w*[Tt]ax\w*\s*\([^}]*\{[^}]*\}',
            r'function\s+change\w*[Ff]ee\w*\s*\([^}]*\{[^}]*\}'
        ]
        for pattern in fee_setter_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                function_body = match.group()
                line_num = code[:match.start()].count('\n') + 1
                # onlyOwner 체크가 있는지 확인
                has_access_control = any([
                    re.search(r'onlyOwner', function_body),
                    re.search(r'require\s*\(\s*msg\.sender\s*==\s*owner', function_body),
                    re.search(r'require\s*\(\s*_msgSender\(\)\s*==\s*owner', function_body)
                ])
                # 최대값 제한이 있는지 확인
                has_max_limit = any([
                    re.search(r'require\s*\(\s*\w+\s*<=\s*\d+', function_body),
                    re.search(r'require\s*\(\s*\w+\s*<\s*\d+', function_body),
                    re.search(r'if\s*\(\s*\w+\s*[><=]+\s*\d+', function_body)
                ])
                if has_access_control and not has_max_limit:
                    findings.append(Finding(
                        pattern_name="Dynamic Fee Manipulation",
                        description="owner가 수수료를 제한 없이 변경할 수 있습니다.",
                        code_snippet=function_body[:300] + "...",
                        line_number=line_num
                    ))
        return findings
    def _detect_asymmetric_fees(self, code: str) -> List[Finding]:
        findings = []
        # 매수/매도 수수료 변수들 찾기
        buy_fee_vars = re.findall(r'(\w*[Bb]uy\w*[Tt]ax\w*|\w*[Bb]uy\w*[Ff]ee\w*)', code)
        sell_fee_vars = re.findall(r'(\w*[Ss]ell\w*[Tt]ax\w*|\w*[Ss]ell\w*[Ff]ee\w*)', code)
        if buy_fee_vars and sell_fee_vars:
            # 각각의 값을 찾아서 비교
            for buy_var in buy_fee_vars:
                buy_assignment = re.search(rf'{buy_var}\s*=\s*(\d+)', code)
                if buy_assignment:
                    buy_value = int(buy_assignment.group(1))
                    for sell_var in sell_fee_vars:
                        sell_assignment = re.search(rf'{sell_var}\s*=\s*(\d+)', code)
                        if sell_assignment:
                            sell_value = int(sell_assignment.group(1))
                            # 매도 수수료가 매수 수수료보다 현저히 높은 경우
                            if sell_value > buy_value * 5 or (buy_value <= 5 and sell_value >= 50):
                                line_num = code[:sell_assignment.start()].count('\n') + 1
                                findings.append(Finding(
                                    pattern_name="Asymmetric Fee Structure",
                                                description=f"매수 수수료({buy_value}%)와 매도 수수료({sell_value}%)가 현저히 비대칭입니다.",
                                    code_snippet=f"{buy_var} = {buy_value}, {sell_var} = {sell_value}",
                                    line_number=line_num
                                ))
        return findings
    def _detect_no_fee_limits(self, code: str) -> List[Finding]:
        findings = []
        # 수수료 설정 함수에서 상한선 체크가 없는 경우
        fee_setter_pattern = r'function\s+set\w*[TtFf][aexe]+\w*\s*\([^}]*\{[^}]*\}'
        matches = re.finditer(fee_setter_pattern, code, re.DOTALL)
        for match in matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # 파라미터 이름 추출
            param_match = re.search(r'\(\s*\w+\s+(\w+)', function_body)
            if param_match:
                param_name = param_match.group(1)
                # 이 파라미터에 대한 제한 체크가 있는지 확인
                has_limit = any([
                    re.search(rf'require\s*\(\s*{param_name}\s*<=\s*\d+', function_body),
                    re.search(rf'require\s*\(\s*{param_name}\s*<\s*\d+', function_body),
                    re.search(rf'if\s*\(\s*{param_name}\s*[><=]+\s*\d+', function_body)
                ])
                if not has_limit:
                    findings.append(Finding(
                        pattern_name="No Fee Limit",
                        description="수수료 설정 함수에 상한선 제한이 없습니다.",
                        code_snippet=function_body[:300] + "...",
                        line_number=line_num
                    ))
        return findings
    def _detect_unexpected_fee_recipient(self, code: str) -> List[Finding]:
        findings = []
        # 수수료 전송 패턴들
        fee_transfer_patterns = [
            r'transfer\s*\(\s*(\w+)\s*,\s*\w*[Ff]ee\w*',
            r'\.transfer\s*\(\s*(\w+)\s*,\s*\w*[Tt]ax\w*',
            r'payable\s*\(\s*(\w+)\s*\)\.transfer',
            r'(\w+)\.transfer\s*\(\s*\w*[Ff]ee\w*'
        ]
        for pattern in fee_transfer_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                recipient = match.group(1) if match.groups() else "unknown"
                # 수수료 수신자가 owner가 아닌 경우 의심
                if recipient not in ['owner', 'feeRecipient', 'teamWallet', 'marketingWallet']:
                    findings.append(Finding(
                        pattern_name="Unexpected Fee Recipient",
                        description=f"수수료가 예상치 못한 주소로 전송됩니다: {recipient}",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_fee_calculation_errors(self, code: str) -> List[Finding]:
        findings = []
        # 잘못된 수수료 계산 패턴들
        wrong_calc_patterns = [
            r'\w+\s*\*\s*\w*[Tt]ax\w*\s*(?!/\s*100)',  # 100으로 나누지 않음
            r'\w+\s*\*\s*\w*[Ff]ee\w*\s*(?!/\s*100)',
            r'amount\s*\*\s*tax\s*(?!/)',
            r'value\s*\*\s*fee\s*(?!/)'
        ]
        for pattern in wrong_calc_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # 실제로 나누기가 없는지 더 정확히 확인
                full_expr = code[match.start():match.end()+50]
                if '/' not in full_expr and '*' in match.group():
                    findings.append(Finding(
                        pattern_name="Fee Calculation Error",
                        description="수수료 계산에서 백분율 변환(나누기)이 누락되었습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_multiple_fees(self, code: str) -> List[Finding]:
        findings = []
        # transfer 함수에서 여러 수수료가 적용되는지 확인
        transfer_pattern = r'function\s+transfer\s*\([^}]*\{[^}]*\}'
        transfer_matches = re.finditer(transfer_pattern, code, re.DOTALL)
        for transfer_match in transfer_matches:
            function_body = transfer_match.group()
            line_num = code[:transfer_match.start()].count('\n') + 1
            # 여러 종류의 수수료 변수들 찾기
            fee_types = []
            fee_patterns = [
                r'\w*[Bb]uy\w*[Tt]ax\w*',
                r'\w*[Ss]ell\w*[Tt]ax\w*',
                r'\w*[Tt]ransfer\w*[Tt]ax\w*',
                r'\w*[Ll]iquidity\w*[Ff]ee\w*',
                r'\w*[Mm]arketing\w*[Ff]ee\w*',
                r'\w*[Dd]ev\w*[Ff]ee\w*',
                r'\w*[Bb]urn\w*[Ff]ee\w*'
            ]
            for pattern in fee_patterns:
                if re.search(pattern, function_body):
                    fee_types.append(pattern)
            if len(fee_types) >= 3:
                findings.append(Finding(
                    pattern_name="Multiple Fee Types",
                    description=f"여러 종류의 수수료가 중첩 적용됩니다: {len(fee_types)}개",
                    code_snippet=f"Fee types found: {fee_types[:3]}...",
                    line_number=line_num
                ))
        return findings