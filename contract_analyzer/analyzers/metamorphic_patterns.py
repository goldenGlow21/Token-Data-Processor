"""
메타모픽/업그레이드 패턴 탐지 모듈
업그레이드 가능성 악용 및 CREATE2/SELFDESTRUCT 패턴을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class MetamorphicPatterns(AnalysisPattern):
    """메타모픽 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_unlimited_upgrades(contract_code))
        findings.extend(self._detect_proxy_manipulation(contract_code))
        findings.extend(self._detect_selfdestruct_patterns(contract_code))
        findings.extend(self._detect_create2_patterns(contract_code))
        findings.extend(self._detect_governance_bypass(contract_code))
        return findings
    def _detect_unlimited_upgrades(self, code: str) -> List[Finding]:
        findings = []
        upgrade_patterns = [
            r'function\s+upgrade\w*.*onlyOwner',
            r'function\s+\w*[Uu]pgrade\w*.*onlyOwner',
            r'function\s+setImplementation.*onlyOwner'
        ]
        for pattern in upgrade_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                function_body = match.group()
                line_num = code[:match.start()].count('\n') + 1
                # 시간 지연이나 제한이 있는지 확인
                has_timelock = any([
                    re.search(r'timelock', function_body, re.IGNORECASE),
                    re.search(r'delay', function_body, re.IGNORECASE),
                    re.search(r'block\.timestamp.*>', function_body)
                ])
                if not has_timelock:
                    findings.append(Finding(
                        pattern_name="Unlimited Upgrades",
                        description="업그레이드에 시간 지연이나 제한이 없습니다.",
                        code_snippet=function_body[:200] + "...",
                        line_number=line_num
                    ))
        return findings
    def _detect_proxy_manipulation(self, code: str) -> List[Finding]:
        findings = []
        proxy_patterns = [
            r'implementation\s*=\s*\w+',
            r'_implementation\s*=\s*\w+',
            r'function\s+\w*[Ii]mplementation\w*.*onlyOwner'
        ]
        for pattern in proxy_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Proxy Implementation Change",
                    description="프록시 구현체를 변경할 수 있는 기능이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_selfdestruct_patterns(self, code: str) -> List[Finding]:
        findings = []
        selfdestruct_patterns = [
            r'selfdestruct\s*\(',
            r'suicide\s*\('
        ]
        for pattern in selfdestruct_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Self Destruct Function",
                    description="컨트랙트 자폭 기능이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_create2_patterns(self, code: str) -> List[Finding]:
        findings = []
        create2_patterns = [
            r'CREATE2',
            r'create2\s*\(',
            r'Clones\.cloneDeterministic'
        ]
        for pattern in create2_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="CREATE2 Usage",
                    description="CREATE2를 사용한 결정적 주소 생성이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_governance_bypass(self, code: str) -> List[Finding]:
        findings = []
        # 거버넌스 우회 패턴들
        bypass_patterns = [
            r'function\s+\w*[Uu]pgrade\w*.*onlyOwner(?!.*vote)',
            r'function\s+\w*[Cc]hange\w*.*onlyOwner(?!.*proposal)',
            r'function\s+setImplementation.*onlyOwner(?!.*timelock)'
        ]
        for pattern in bypass_patterns:
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Governance Bypass",
                    description="거버넌스 투표 없이 중요한 변경이 가능합니다.",
                    code_snippet=match.group()[:200] + "...",
                    line_number=line_num
                ))
        return findings