"""
민팅 관련 악성 패턴 탐지 모듈
무제한/숨겨진 민팅 및 공급량 조작을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class MintingPatterns(AnalysisPattern):
    """민팅 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        # 무제한 민팅 함수 탐지
        findings.extend(self._detect_unlimited_minting(contract_code))
        # 숨겨진 민팅 탐지
        findings.extend(self._detect_hidden_minting(contract_code))
        # 조건부 대량 민팅 탐지
        findings.extend(self._detect_conditional_mass_minting(contract_code))
        # totalSupply 직접 조작 탐지
        findings.extend(self._detect_total_supply_manipulation(contract_code))
        # 최대 공급량 무시 탐지
        findings.extend(self._detect_max_supply_bypass(contract_code))
        # 잔액 직접 할당 탐지
        findings.extend(self._detect_direct_balance_assignment(contract_code))
        return findings
    def _detect_unlimited_minting(self, code: str) -> List[Finding]:
        findings = []
        # mint 함수 찾기
        mint_pattern = r'function\s+\w*[Mm]int\w*\s*\([^}]*\{[^}]*\}'
        mint_matches = re.finditer(mint_pattern, code, re.DOTALL)
        for match in mint_matches:
            function_body = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # 양 제한이 없는지 확인
            has_amount_limit = any([
                re.search(r'require\s*\(\s*\w*[Aa]mount\w*\s*<=', function_body),
                re.search(r'require\s*\(\s*\w*[Aa]mount\w*\s*<', function_body),
                re.search(r'if\s*\(\s*\w*[Aa]mount\w*\s*[<>]=?', function_body),
                re.search(r'maxSupply', function_body),
                re.search(r'totalSupply.*[+].*<=', function_body)
            ])
            if not has_amount_limit:
                findings.append(Finding(
                    pattern_name="Unlimited Minting",
                    description="민팅 함수에 양 제한이 없어 무제한으로 토큰을 발행할 수 있습니다.",
                    code_snippet=function_body[:300] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_hidden_minting(self, code: str) -> List[Finding]:
        findings = []
        # 일반 함수들 (transfer, approve 등)에서 mint 호출하는 패턴
        normal_functions = [
            r'function\s+transfer\s*\([^}]*\{[^}]*\}',
            r'function\s+approve\s*\([^}]*\{[^}]*\}',
            r'function\s+transferFrom\s*\([^}]*\{[^}]*\}',
            r'function\s+\w+\s*\([^}]*\{[^}]*\}'
        ]
        mint_calls = [
            r'_mint\s*\(',
            r'mint\s*\(',
            r'balanceOf\s*\[\s*\w+\s*\]\s*\+=',
            r'totalSupply\s*\+=',
            r'\.mint\s*\('
        ]
        for func_pattern in normal_functions:
            func_matches = re.finditer(func_pattern, code, re.DOTALL)
            for func_match in func_matches:
                function_body = func_match.group()
                function_name = re.search(r'function\s+(\w+)', function_body)
                if function_name and not 'mint' in function_name.group(1).lower():
                    # 이 함수가 mint 관련이 아닌데 mint를 호출하는지 확인
                    for mint_pattern in mint_calls:
                        if re.search(mint_pattern, function_body):
                            line_num = code[:func_match.start()].count('\n') + 1
                            findings.append(Finding(
                                pattern_name="Hidden Minting",
                                description=f"{function_name.group(1)} 함수 내부에 숨겨진 민팅 로직이 있습니다.",
                                code_snippet=function_body[:300] + "...",
                                line_number=line_num
                            ))
                            break
        return findings
    def _detect_conditional_mass_minting(self, code: str) -> List[Finding]:
        findings = []
        # 조건부 대량 민팅 패턴들
        mass_mint_patterns = [
            r'balanceOf\s*\[\s*owner\s*\]\s*\+=\s*totalSupply',
            r'balanceOf\s*\[\s*\w+\s*\]\s*\+=\s*\d{7,}',  # 1000만 이상
            r'_mint\s*\(\s*\w+\s*,\s*totalSupply\s*\)',
            r'totalSupply\s*\*=\s*\d+',
            r'balanceOf\s*\[\s*\w+\s*\]\s*=\s*totalSupply'
        ]
        for pattern in mass_mint_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # 이것이 조건문 안에 있는지 확인
                before_code = code[:match.start()]
                if_count = before_code.count('if (') + before_code.count('if(')
                brace_count = before_code.count('{')
                if if_count > 0 or brace_count > 0:
                    findings.append(Finding(
                        pattern_name="Conditional Mass Minting",
                            description="특정 조건에서 대량의 토큰을 민팅하는 로직이 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_total_supply_manipulation(self, code: str) -> List[Finding]:
        findings = []
        # totalSupply 직접 수정 패턴들
        total_supply_patterns = [
            r'totalSupply\s*=\s*\d+',
            r'totalSupply\s*\+=\s*\d+',
            r'totalSupply\s*\*=\s*\d+',
            r'totalSupply\s*=\s*\w+',
            r'totalSupply\s*\-=\s*\d+'
        ]
        for pattern in total_supply_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # constructor나 초기화 함수가 아닌 곳에서 수정하는지 확인
                context = code[max(0, match.start()-200):match.end()+200]
                is_constructor = re.search(r'constructor\s*\(', context) or re.search(r'function\s+initialize', context)
                if not is_constructor:
                    findings.append(Finding(
                        pattern_name="Total Supply Manipulation",
                        description="totalSupply 값을 직접 수정하는 코드가 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _detect_max_supply_bypass(self, code: str) -> List[Finding]:
        findings = []
        # maxSupply 변수가 있는지 확인
        max_supply_exists = re.search(r'\w*[Mm]axSupply\w*', code)
        if max_supply_exists:
            # mint 함수들에서 maxSupply 체크가 없는지 확인
            mint_pattern = r'function\s+\w*[Mm]int\w*\s*\([^}]*\{[^}]*\}'
            mint_matches = re.finditer(mint_pattern, code, re.DOTALL)
            for match in mint_matches:
                function_body = match.group()
                line_num = code[:match.start()].count('\n') + 1
                # maxSupply 체크가 있는지 확인
                has_max_supply_check = re.search(r'maxSupply', function_body)
                if not has_max_supply_check:
                    findings.append(Finding(
                        pattern_name="Max Supply Bypass",
                        description="maxSupply가 정의되어 있지만 민팅 함수에서 체크하지 않습니다.",
                        code_snippet=function_body[:300] + "...",
                        line_number=line_num
                    ))
        return findings
    def _detect_direct_balance_assignment(self, code: str) -> List[Finding]:
        findings = []
        # 잔액 직접 할당 패턴들
        balance_patterns = [
            r'balanceOf\s*\[\s*\w+\s*\]\s*=\s*\d+',
            r'balanceOf\s*\[\s*\w+\s*\]\s*=\s*\w+',
            r'_balances\s*\[\s*\w+\s*\]\s*=\s*\d+',
            r'_balances\s*\[\s*\w+\s*\]\s*=\s*\w+'
        ]
        for pattern in balance_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # constructor나 mint 함수가 아닌 곳에서 할당하는지 확인
                context = code[max(0, match.start()-300):match.end()+300]
                is_valid_context = any([
                    re.search(r'constructor\s*\(', context),
                    re.search(r'function\s+\w*[Mm]int\w*', context),
                    re.search(r'function\s+initialize', context)
                ])
                if not is_valid_context:
                    findings.append(Finding(
                        pattern_name="Direct Balance Assignment",
                        description="잔액을 직접 할당하는 코드가 있습니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings