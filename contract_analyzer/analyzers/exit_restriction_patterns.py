"""
출구 제한 패턴 탐지 모듈
토큰 매도/출금 경로를 제한하는 악성 패턴을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class ExitRestrictionPatterns(AnalysisPattern):
    """출구 제한 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        # DEX 매도 경로 차단 탐지
        findings.extend(self._detect_sell_path_block(contract_code))
        # Pausable 기반 출구 제한 탐지
        findings.extend(self._detect_pausable_exit_block(contract_code))
        # Owner 권한 남용 탐지
        findings.extend(self._detect_owner_privilege_abuse(contract_code))
        # 베스팅 우회 탐지
        findings.extend(self._detect_vesting_bypass(contract_code))
        # 리베이스 조작 탐지
        findings.extend(self._detect_rebase_manipulation(contract_code))
        return findings
    def _detect_sell_path_block(self, code: str) -> List[Finding]:
        """DEX Pair 전송/스왑 등 매도 경로에서만 실패하는 로직 탐지"""
        findings = []
        # DEX 관련 변수들 탐지
        dex_variables = self._find_dex_variables(code)
        if not dex_variables:
            return findings
        # transfer 계열 함수들에서 DEX 관련 제한 로직 탐지
        transfer_functions = self._find_transfer_functions(code)
        for func_match in transfer_functions:
            func_body = func_match.group()
            func_start = func_match.start()
            # DEX Pair에 대한 제한 로직 확인
            restrictions = self._check_dex_restrictions_in_function(func_body, dex_variables)
            for restriction in restrictions:
                line_num = code[:func_start + restriction['position']].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Sell-Path Block",
                    description="DEX Pair로의 전송/스왑을 차단하여 매도 경로를 제한하는 로직이 발견되었습니다.",
                    code_snippet=restriction['code'],
                    line_number=line_num
                ))
        # 스왑 함수에서 일방향 제한 탐지
        swap_restrictions = self._detect_swap_restrictions(code, dex_variables)
        findings.extend(swap_restrictions)
        # AMM/DEX 상호작용 차단 탐지
        amm_blocks = self._detect_amm_interaction_blocks(code, dex_variables)
        findings.extend(amm_blocks)
        return findings
    def _find_dex_variables(self, code: str) -> List[str]:
        """DEX 관련 변수들을 찾아서 반환"""
        dex_variables = []
        # DEX Pair 관련 변수 패턴들
        dex_patterns = [
            # Uniswap 스타일 인터페이스
            r'IUniswapV2Pair\s+public\s+(\w+);',
            r'IUniswapV2Pair\s+(\w+);',
            # address 타입 변수들 (세미콜론으로 끝나는 것만)
            r'address\s+public\s+(\w+(?:Pair|pair|DEX|dex|Swap|swap|Pool|pool|Router|router|AMM|amm)\w*);',
            r'address\s+(\w+(?:Pair|pair|DEX|dex|Swap|swap|Pool|pool|Router|router|AMM|amm)\w*);',
            # 특정 키워드를 포함한 변수명들
            r'address\s+public\s+(uniswap\w*);',
            r'address\s+(uniswap\w*);',
            r'address\s+public\s+(pancake\w*);',
            r'address\s+(pancake\w*);',
            r'address\s+public\s+(sushi\w*);',
            r'address\s+(sushi\w*);',
            # mapping 타입
            r'mapping\s*\([^)]*\)\s*public\s*(is\w*);',
            r'mapping\s*\([^)]*\)\s*(is\w*);',
            # 더 구체적인 패턴들
            r'IUniswapV2Router\w*\s+public\s+(\w+);',
            r'IUniswapV2Router\w*\s+(\w+);',
            r'IPancake\w*\s+public\s+(\w+);',
            r'IPancake\w*\s+(\w+);'
        ]
        for pattern in dex_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                var_name = match.group(1)
                if var_name and var_name not in dex_variables:
                    dex_variables.append(var_name)
        return dex_variables
    def _find_transfer_functions(self, code: str) -> List[re.Match]:
        """transfer 계열 함수들을 찾아서 반환"""
        function_patterns = [
            r'function\s+transfer\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}',
            r'function\s+transferFrom\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}',
            r'function\s+_transfer\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}',
            r'function\s+\w*[Tt]ransfer\w*\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}'
        ]
        functions = []
        for pattern in function_patterns:
            matches = re.finditer(pattern, code, re.DOTALL | re.IGNORECASE)
            functions.extend(matches)
        return functions
    def _check_dex_restrictions_in_function(self, func_body: str, dex_variables: List[str]) -> List[dict]:
        """함수 내에서 DEX 관련 제한 로직을 확인"""
        restrictions = []
        # 모든 require 문과 if 문을 찾아서 DEX 관련 제한인지 확인
        restriction_patterns = [
            r'require\s*\([^)]+\)',
            r'if\s*\([^)]+\)\s*\{[^}]*revert[^}]*\}',
            r'if\s*\([^)]+\)\s*\{[^}]*return\s+false[^}]*\}'
        ]
        for pattern in restriction_patterns:
            matches = re.finditer(pattern, func_body, re.DOTALL | re.IGNORECASE)
            for match in matches:
                statement = match.group()
                # 이 statement가 DEX 제한과 관련된지 확인
                if self._is_dex_restriction(statement, dex_variables):
                    restrictions.append({
                        'code': statement,
                        'position': match.start(),
                        'description': self._get_restriction_description(statement, dex_variables),
                        'dex_variable': self._get_related_dex_variable(statement, dex_variables)
                    })
        return restrictions
    def _is_dex_restriction(self, statement: str, dex_variables: List[str]) -> bool:
        """statement가 DEX 제한과 관련된지 확인"""
        # DEX 변수명이 포함되어 있는지 확인
        for dex_var in dex_variables:
            if dex_var in statement:
                return True
        # 매도/매수 관련 키워드가 포함되어 있는지 확인
        sell_keywords = ['sell', 'Sell', 'pair', 'Pair', 'swap', 'Swap', 'buyOnly', 'sellEnabled']
        for keyword in sell_keywords:
            if keyword in statement:
                return True
        # tx.origin 체크 (DEX 상호작용 차단)
        if 'tx.origin' in statement and 'msg.sender' in statement:
            return True
        return False
    def _get_restriction_description(self, statement: str, dex_variables: List[str]) -> str:
        """제한 로직의 설명을 생성"""
        # DEX 변수 관련
        for dex_var in dex_variables:
            if dex_var in statement:
                if '!=' in statement or 'revert' in statement:
                    return f'DEX Pair({dex_var})로의 전송 차단'
                elif '==' in statement and 'from' in statement:
                    return f'DEX Pair({dex_var})에서만 전송 허용 (매수만 가능)'
                else:
                    return f'DEX Pair({dex_var}) 관련 제한'
        # 일반적인 패턴들
        if 'sellEnabled' in statement and '!' in statement:
            return '매도 기능 비활성화'
        elif 'buyOnly' in statement:
            return '매수 전용 모드'
        elif 'tx.origin' in statement:
            return 'AMM/DEX 상호작용 차단 (컨트랙트 호출 금지)'
        elif 'pair' in statement.lower() and '[to]' in statement:
            return 'Pair 매핑을 통한 매도 경로 차단'
        return 'DEX 관련 제한 로직'
    def _get_related_dex_variable(self, statement: str, dex_variables: List[str]) -> str:
        """관련된 DEX 변수를 찾아서 반환"""
        for dex_var in dex_variables:
            if dex_var in statement:
                return dex_var
        return 'general'
    def _detect_swap_restrictions(self, code: str, dex_variables: List[str]) -> List[Finding]:
        """스왑 함수에서의 일방향 제한 탐지"""
        findings = []
        # 스왑 관련 함수들 찾기
        swap_patterns = [
            r'function\s+swap\w*\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}',
            r'function\s+\w*[Ss]wap\w*\s*\([^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}'
        ]
        for pattern in swap_patterns:
            matches = re.finditer(pattern, code, re.DOTALL | re.IGNORECASE)
            for match in matches:
                func_body = match.group()
                # 일방향 스왑만 허용하는 패턴들
                one_way_patterns = [
                    r'require\s*\(\s*amount0Out\s*==\s*0\s*\)',  # 한 방향만 허용
                    r'require\s*\(\s*amount1Out\s*==\s*0\s*\)',
                    r'require\s*\(\s*amount0In\s*>\s*0\s*&&\s*amount1Out\s*==\s*0\s*\)',  # 매수만
                    r'require\s*\(\s*amount1In\s*>\s*0\s*&&\s*amount0Out\s*==\s*0\s*\)'
                ]
                for one_way_pattern in one_way_patterns:
                    if re.search(one_way_pattern, func_body, re.IGNORECASE):
                        line_num = code[:match.start()].count('\n') + 1
                        findings.append(Finding(
                            pattern_name="One-Way Swap Restriction",
                                description="스왑 함수에서 일방향 거래만 허용하여 매도를 차단하는 로직이 있습니다.",
                            code_snippet=func_body[:300] + "..." if len(func_body) > 300 else func_body,
                            line_number=line_num
                        ))
                        break
        return findings
    def _detect_amm_interaction_blocks(self, code: str, dex_variables: List[str]) -> List[Finding]:
        """AMM/DEX 상호작용 차단 패턴 탐지"""
        findings = []
        # AMM 상호작용 차단 패턴들
        amm_block_patterns = [
            # DEX Router 호출 차단
            r'require\s*\(\s*msg\.sender\s*!=\s*\w*[Rr]outer\w*\s*\)',
            # Pair 컨트랙트 호출 차단
            r'require\s*\(\s*msg\.sender\s*!=\s*\w*[Pp]air\w*\s*\)',
            # 컨트랙트에서의 호출 차단 (EOA만 허용)
            r'require\s*\(\s*tx\.origin\s*==\s*msg\.sender\s*\)',
            # Factory에서 생성된 Pair 차단
            r'require\s*\(\s*!\s*isContract\s*\(\s*msg\.sender\s*\)\s*\)',
            # 특정 함수 시그니처 차단 (스왑 관련)
            r'require\s*\(\s*msg\.data\.length\s*!=\s*\d+\s*\)',  # 스왑 함수 길이 차단
        ]
        for pattern in amm_block_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                # 이 패턴이 transfer나 중요한 함수 내부에 있는지 확인
                if self._is_in_critical_function(code, match.start()):
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append(Finding(
                        pattern_name="AMM Interaction Block",
                        description="AMM/DEX와의 상호작용을 차단하여 매도 경로를 제한하는 로직입니다.",
                        code_snippet=match.group(),
                        line_number=line_num
                    ))
        return findings
    def _is_in_critical_function(self, code: str, position: int) -> bool:
        """해당 위치가 중요한 함수(transfer, approve 등) 내부에 있는지 확인"""
        # 해당 위치 이전의 코드에서 가장 가까운 함수 찾기
        before_code = code[:position]
        # 중요한 함수들의 패턴
        critical_functions = [
            r'function\s+transfer\s*\(',
            r'function\s+transferFrom\s*\(',
            r'function\s+_transfer\s*\(',
            r'function\s+approve\s*\(',
            r'function\s+swap\w*\s*\(',
            r'function\s+\w*[Ss]wap\w*\s*\('
        ]
        for func_pattern in critical_functions:
            matches = list(re.finditer(func_pattern, before_code, re.IGNORECASE))
            if matches:
                # 가장 마지막 매치가 이 위치와 가장 가까운 함수
                last_match = matches[-1]
                # 해당 함수의 끝을 찾아서 position이 그 안에 있는지 확인
                func_start = last_match.start()
                func_end = self._find_function_end(code, func_start)
                if func_start <= position <= func_end:
                    return True
        return False
    def _find_function_end(self, code: str, func_start: int) -> int:
        """함수의 끝 위치를 찾기"""
        brace_count = 0
        in_function = False
        for i in range(func_start, len(code)):
            char = code[i]
            if char == '{':
                brace_count += 1
                in_function = True
            elif char == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    return i
        return len(code)

    def _detect_pausable_exit_block(self, code: str) -> List[Finding]:
        """pause 기능을 이용한 선택적 매도 차단 탐지"""
        findings = []

        # Pausable 상속 또는 pause 변수 확인
        if not self._has_pausable_functionality(code):
            return findings

        # transfer 함수들에서 whenNotPaused 확인
        pausable_functions = self._find_pausable_transfer_functions(code)

        for func_info in pausable_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Pausable Exit Block",
                description="pause 기능을 통해 사용자의 토큰 전송을 일시적으로 차단할 수 있습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        # Owner만 pause에서 예외되는 함수들 탐지
        owner_bypass_functions = self._find_owner_bypass_functions(code)

        for func_info in owner_bypass_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Owner Pause Bypass",
                description="Owner만 pause 상태에서도 작업을 수행할 수 있어 불공정한 우위를 갖습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        return findings

    def _detect_owner_privilege_abuse(self, code: str) -> List[Finding]:
        """Owner의 과도한 권한 남용 탐지"""
        findings = []

        # Owner의 무제한 토큰 발행 권한
        unlimited_mint_functions = self._find_unlimited_mint_functions(code)

        for func_info in unlimited_mint_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Unlimited Token Issuance",
                description="Owner가 제한 없이 새로운 토큰을 발행할 수 있어 기존 보유자의 지분을 희석시킬 수 있습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        # 소유권 포기 불가능한 구조
        if not self._has_ownership_renunciation(code):
            findings.append(Finding(
                pattern_name="Permanent Owner Control",
                description="소유권을 포기할 수 있는 기능이 없어 Owner가 영구적으로 시스템을 통제할 수 있습니다.",
                code_snippet="No renounceOwnership() function found",
                line_number=1
            ))

        return findings

    def _detect_vesting_bypass(self, code: str) -> List[Finding]:
        """Owner가 베스팅 제약을 우회하는 패턴 탐지"""
        findings = []

        # 베스팅 시스템 존재 확인
        if not self._has_vesting_system(code):
            return findings

        # Owner가 베스팅 없이 토큰을 배포하는 함수들
        bypass_functions = self._find_vesting_bypass_functions(code)

        for func_info in bypass_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Vesting System Bypass",
                description="Owner는 베스팅 제약 없이 토큰을 배포할 수 있어 불공정한 우위를 갖습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        return findings

    def _detect_rebase_manipulation(self, code: str) -> List[Finding]:
        """리베이스를 통한 토큰 공급량 조작 탐지"""
        findings = []

        # 리베이스 시스템 존재 확인
        rebase_functions = self._find_rebase_functions(code)

        for func_info in rebase_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Rebase Manipulation Risk",
                description="리베이스 기능을 통해 토큰 공급량을 조작하여 사용자의 토큰 가치를 희석시킬 수 있습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        # Owner가 리베이스 컨트랙트 주소를 임의로 설정할 수 있는지 확인
        rebase_control_functions = self._find_rebase_control_functions(code)

        for func_info in rebase_control_functions:
            line_num = code[:func_info['position']].count('\n') + 1
            findings.append(Finding(
                pattern_name="Rebase Contract Control",
                description="Owner가 리베이스 컨트랙트 주소를 임의로 설정하여 토큰 공급량을 조작할 수 있습니다.",
                code_snippet=func_info['code'],
                line_number=line_num
            ))

        return findings

    # === 헬퍼 함수들 ===

    def _has_pausable_functionality(self, code: str) -> bool:
        """Pausable 기능이 있는지 확인"""
        pausable_patterns = [
            r'contract\s+\w+\s+is\s+.*Pausable',
            r'bool\s+.*paused',
            r'modifier\s+whenNotPaused',
            r'modifier\s+whenPaused',
            r'function\s+pause\s*\(',
            r'function\s+unpause\s*\('
        ]

        for pattern in pausable_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False

    def _find_pausable_transfer_functions(self, code: str) -> List[dict]:
        """whenNotPaused가 적용된 transfer 함수들 찾기"""
        functions = []

        # transfer 함수에 whenNotPaused 모디파이어가 있는 패턴
        pausable_transfer_pattern = r'function\s+(transfer\w*|_transfer)\s*\([^)]*\)\s+[^{]*whenNotPaused[^{]*\{'

        matches = re.finditer(pausable_transfer_pattern, code, re.IGNORECASE | re.DOTALL)
        for match in matches:
            functions.append({
                'code': match.group()[:200] + "...",
                'position': match.start()
            })

        return functions

    def _find_owner_bypass_functions(self, code: str) -> List[dict]:
        """Owner만 pause에서 예외되는 함수들 찾기"""
        functions = []

        # onlyOwner는 있지만 whenNotPaused가 없는 함수들
        owner_only_pattern = r'function\s+\w+\s*\([^)]*\)\s+[^{]*onlyOwner(?![^{]*whenNotPaused)[^{]*\{'

        matches = re.finditer(owner_only_pattern, code, re.IGNORECASE | re.DOTALL)
        for match in matches:
            # 토큰 발행이나 전송과 관련된 함수인지 확인
            func_body = match.group()
            if any(keyword in func_body.lower() for keyword in ['transfer', 'mint', 'send', 'tokens']):
                functions.append({
                    'code': match.group()[:200] + "...",
                    'position': match.start()
                })

        return functions

    def _find_unlimited_mint_functions(self, code: str) -> List[dict]:
        """무제한 토큰 발행 함수들 찾기"""
        functions = []

        # Owner가 제한 없이 토큰을 발행할 수 있는 함수들
        mint_patterns = [
            r'function\s+\w*mint\w*\s*\([^)]*\)\s+[^{]*onlyOwner[^{]*\{[^}]*(?!require\s*\([^)]*<=|require\s*\([^)]*<)[^}]*\}',
            r'function\s+send\w*[Tt]okens?\w*\s*\([^)]*\)\s+[^{]*onlyOwner[^{]*\{',
            r'function\s+\w*[Ii]ssue\w*\s*\([^)]*\)\s+[^{]*onlyOwner[^{]*\{'
        ]

        for pattern in mint_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                functions.append({
                    'code': match.group()[:300] + "...",
                    'position': match.start()
                })

        return functions

    def _has_ownership_renunciation(self, code: str) -> bool:
        """소유권 포기 기능이 있는지 확인"""
        renounce_patterns = [
            r'function\s+renounceOwnership\s*\(',
            r'function\s+renounce\s*\(',
            r'owner\s*=\s*address\s*\(\s*0\s*\)'
        ]

        for pattern in renounce_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False

    def _has_vesting_system(self, code: str) -> bool:
        """베스팅 시스템이 있는지 확인"""
        vesting_patterns = [
            r'mapping\s*\([^)]*\)\s*\w*[Vv]esting\w*',
            r'mapping\s*\([^)]*\)\s*\w*[Ll]ock\w*',
            r'lockingTime|vestingPeriod|releaseTime',
            r'function\s+\w*[Vv]est\w*',
            r'function\s+\w*[Rr]elease\w*'
        ]

        for pattern in vesting_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False

    def _find_vesting_bypass_functions(self, code: str) -> List[dict]:
        """베스팅 제약을 우회하는 함수들 찾기"""
        functions = []

        # Owner가 베스팅 없이 직접 토큰을 배포하는 함수들
        bypass_patterns = [
            r'function\s+send\w*[Tt]okens?\w*\s*\([^)]*\)\s+[^{]*onlyOwner[^{]*\{[^}]*(?!vesting|lock|release)[^}]*\}',
            r'function\s+\w*[Dd]istribute\w*\s*\([^)]*\)\s+[^{]*onlyOwner[^{]*\{'
        ]

        for pattern in bypass_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                functions.append({
                    'code': match.group()[:300] + "...",
                    'position': match.start()
                })

        return functions

    def _find_rebase_functions(self, code: str) -> List[dict]:
        """리베이스 함수들 찾기"""
        functions = []

        rebase_patterns = [
            r'function\s+rebase\s*\([^)]*\)',
            r'function\s+\w*[Rr]ebase\w*\s*\([^)]*\)',
            r'_totalSupply\s*=\s*_totalSupply\.\w+\(',
            r'_gonsPerFragment\s*='
        ]

        for pattern in rebase_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                functions.append({
                    'code': match.group(),
                    'position': match.start()
                })

        return functions

    def _find_rebase_control_functions(self, code: str) -> List[dict]:
        """리베이스 컨트랙트 주소를 설정하는 함수들 찾기"""
        functions = []

        control_patterns = [
            r'function\s+set\w*[Rr]ebase\w*[Aa]ddress\s*\([^)]*\)\s+[^{]*onlyOwner',
            r'function\s+set\w*[Rr]ebase\w*[Cc]ontract\s*\([^)]*\)\s+[^{]*onlyOwner',
            r'reBaseContractAddress\s*=',
            r'rebaseContract\s*='
        ]

        for pattern in control_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                functions.append({
                    'code': match.group(),
                    'position': match.start()
                })

        return functions