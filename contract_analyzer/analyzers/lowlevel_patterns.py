"""
Low-level 조작 탐지 모듈
Assembly 악용 및 상태 변수 조작을 탐지합니다.
"""
import re
from typing import List
from contract_analyzer import AnalysisPattern, Finding
class LowLevelPatterns(AnalysisPattern):
    """Low-level 패턴 분석기"""
    def analyze(self, contract_code: str) -> List[Finding]:
        findings = []
        findings.extend(self._detect_inline_assembly(contract_code))
        findings.extend(self._detect_storage_manipulation(contract_code))
        findings.extend(self._detect_memory_manipulation(contract_code))
        findings.extend(self._detect_direct_storage_access(contract_code))
        return findings
    def _detect_inline_assembly(self, code: str) -> List[Finding]:
        findings = []
        assembly_pattern = r'assembly\s*\{[^}]*\}'
        matches = re.finditer(assembly_pattern, code, re.DOTALL)
        for match in matches:
            assembly_block = match.group()
            line_num = code[:match.start()].count('\n') + 1
            # 의심스러운 assembly 명령어들
            suspicious_ops = [
                ('sstore', '스토리지 직접 쓰기'),
                ('sload', '스토리지 직접 읽기'),
                ('delegatecall', 'delegatecall 호출'),
                ('selfdestruct', '컨트랙트 자폭'),
                ('suicide', '컨트랙트 자폭 (구버전)')
            ]
            for op, description in suspicious_ops:
                if re.search(op, assembly_block, re.IGNORECASE):
                    findings.append(Finding(
                        pattern_name="Suspicious Inline Assembly",
                        description=f"Assembly 블록에서 {description}를 수행합니다.",
                        code_snippet=assembly_block[:300] + "...",
                        line_number=line_num
                    ))
                    break
        return findings
    def _detect_storage_manipulation(self, code: str) -> List[Finding]:
        findings = []
        # Assembly에서 sstore 패턴
        sstore_pattern = r'assembly\s*\{[^}]*sstore\s*\([^}]*\}'
        matches = re.finditer(sstore_pattern, code, re.DOTALL | re.IGNORECASE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append(Finding(
                pattern_name="Direct Storage Manipulation",
                description="Assembly를 통해 스토리지를 직접 조작합니다.",
                code_snippet=match.group()[:200] + "...",
                line_number=line_num
            ))
        return findings
    def _detect_memory_manipulation(self, code: str) -> List[Finding]:
        findings = []
        memory_patterns = [
            (r'mstore\s*\(', '메모리 직접 쓰기'),
            (r'mload\s*\(', '메모리 직접 읽기'),
            (r'returndatacopy\s*\(', '리턴 데이터 복사'),
            (r'codecopy\s*\(', '코드 복사')
        ]
        for pattern, description in memory_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Memory Manipulation",
                    description=f"Assembly에서 {description}를 수행합니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings
    def _detect_direct_storage_access(self, code: str) -> List[Finding]:
        findings = []
        # storage 포인터 사용 패턴
        storage_patterns = [
            r'\w+\s+storage\s+\w+',
            r'storage\s+\w+\s*=',
            r'\.slot\s*=',
            r'\.offset\s*='
        ]
        for pattern in storage_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    pattern_name="Direct Storage Access",
                    description="storage 포인터를 통한 직접적인 스토리지 접근이 있습니다.",
                    code_snippet=match.group(),
                    line_number=line_num
                ))
        return findings