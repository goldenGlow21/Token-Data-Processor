"""
경제적 로직 조작 탐지 모듈
가격/비율 조작 및 유동성/스테이킹 조작을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class EconomicPatterns(AnalysisPattern):
    """경제적 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_hardcoded_prices(contract_code))
        findings.extend(self._detect_manipulable_oracle(contract_code))
        findings.extend(self._detect_liquidity_withdrawal(contract_code))
        findings.extend(self._detect_staking_locks(contract_code))
        return findings
    def _detect_hardcoded_prices(self, code: str) -> List[Finding]:
        findings = []
        price_patterns = [
            r'price\s*=\s*\d+',
            r'rate\s*=\s*\d+',
            r'exchangeRate\s*=\s*\d+'
        ]
        for pattern in price_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Hardcoded Price",
                    description="하드코딩된 가격이나 환율이 사용됩니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_manipulable_oracle(self, code: str) -> List[Finding]:
        findings = []
        oracle_setter_patterns = [
            r'function\s+setPrice.*onlyOwner',
            r'function\s+updatePrice.*onlyOwner',
            r'function\s+setOracle.*onlyOwner'
        ]
        for pattern in oracle_setter_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Manipulable Oracle",
                    description="owner가 오라클 가격을 임의로 변경할 수 있습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_liquidity_withdrawal(self, code: str) -> List[Finding]:
        findings = []
        liquidity_patterns = [
            r'function\s+removeLiquidity.*onlyOwner',
            r'function\s+withdrawLiquidity.*onlyOwner',
            r'lpToken\.transfer\s*\(\s*owner'
        ]
        for pattern in liquidity_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Liquidity Withdrawal",
                    description="owner가 유동성을 임의로 제거할 수 있습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings
    def _detect_staking_locks(self, code: str) -> List[Finding]:
        findings = []
        # 출금 불가능한 스테이킹 패턴
        withdraw_patterns = [
            r'function\s+withdraw.*require\s*\(\s*false',
            r'function\s+unstake.*revert',
            r'function\s+claim.*require\s*\(\s*1\s*==\s*2'
        ]
        for pattern in withdraw_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Staking Lock",
                    description="스테이킹된 토큰을 출금할 수 없습니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings