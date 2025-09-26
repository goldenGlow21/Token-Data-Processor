#!/usr/bin/env python3
import json
import sys
import hashlib
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from common.types import AnalysisReport, AnalysisType


class TokenDataProcessor:
    """Main processor for token data analysis"""

    def __init__(self):
        pass

    def load_input_data(self, input_file: str) -> Dict[str, Any]:
        """Load and parse the input JSON file"""
        with open(input_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def calculate_source_hash(self, source_code: str) -> str:
        """Calculate SHA256 hash of source code"""
        return hashlib.sha256(source_code.encode('utf-8')).hexdigest()

    def preprocess_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess data for STE category detection model"""
        processed = {
            'source_code': data.get('SourceCode', ''),
            'contract_name': data.get('ContractName', ''),
            'compiler_version': data.get('CompilerVersion', ''),
            'optimization_used': data.get('OptimizationUsed', '0') == '1',
            'runs': int(data.get('Runs', '0')),
            'license_type': data.get('LicenseType', ''),
            'proxy_status': data.get('Proxy', '0') == '1'
        }
        return processed

    def _get_analyzer(self, analysis_type: AnalysisType):
        """Get appropriate analyzer based on analysis type"""
        if analysis_type == AnalysisType.SOURCE_CODE:
            from contract_analyzer.contract_analyzer import ContractAnalyzer
            return ContractAnalyzer()
        elif analysis_type == AnalysisType.BYTECODE:
            from bytecode_analyzer.bytecode_analyzer import BytecodeAnalyzer
            return BytecodeAnalyzer()
        else:
            raise ValueError(f"Unsupported analysis type: {analysis_type}")

    def analyze_with_contract_analyzer(self, source_code: str) -> Dict[str, Any]:
        """Legacy method for backward compatibility"""
        try:
            analyzer = self._get_analyzer(AnalysisType.SOURCE_CODE)
            return analyzer.analyze_contract(source_code)
        except Exception as e:
            return {"error": str(e), "summary": {"total_issues": 0, "pattern_counts": {}}, "findings": []}

    def analyze_with_bytecode_analyzer(self, bytecode: str) -> Dict[str, Any]:
        """Legacy method for backward compatibility"""
        try:
            analyzer = self._get_analyzer(AnalysisType.BYTECODE)
            return analyzer.analyze_bytecode(bytecode)
        except Exception as e:
            return {"error": str(e), "summary": {"total_issues": 0, "pattern_counts": {}}, "findings": []}

    def analyze(self, content: str, analysis_type: AnalysisType, **kwargs) -> AnalysisReport:
        """
        Unified analysis method using the new architecture

        Args:
            content: Source code or bytecode to analyze
            analysis_type: Type of analysis to perform
            **kwargs: Additional parameters

        Returns:
            Analysis report
        """
        try:
            analyzer = self._get_analyzer(analysis_type)
            return analyzer.analyze(content, **kwargs)
        except Exception as e:
            # Return error report
            from common.types import AnalysisResult, AnalysisReport
            error_result = AnalysisResult(
                pattern_name="Analysis Error",
                findings=[],
                error=str(e)
            )
            return AnalysisReport(
                analysis_type=analysis_type,
                target_hash=hashlib.sha256(content.encode('utf-8')).hexdigest(),
                contract_name=kwargs.get('contract_name', 'Unknown'),
                results=[error_result]
            )

    def calculate_risk_score(self, analysis_result: Dict[str, Any]) -> int:
        """Calculate risk score based on pattern occurrences with weight coefficients"""
        if 'summary' not in analysis_result:
            return 100

        pattern_counts = analysis_result['summary'].get('pattern_counts', {})

        # Pattern weight coefficients based on maliciousness likelihood
        pattern_weights = {
            # Definitely malicious patterns (high coefficient)
            'Direct Balance Assignment': 20.0,     # 직접 잔액 조작 = 확실한 스캠
            'Balance Manipulation': 18.0,          # 잔액 조작 = 확실한 스캠
            'Asymmetric Fee Structure': 15.0,      # 비대칭 수수료 = 허니팟 특성

            # Very suspicious patterns (medium-high coefficient)
            'Reentrancy Vulnerability': 10.0,      # 재진입 공격 취약점

            # Could be legitimate but concerning (medium coefficient)
            'Approve Function Manipulation': 3.0,  # approve 보안 조치 (정상일 수도)
            'Hidden Minting': 2.0,                 # 숨겨진 민팅 (중앙화 토큰에선 가능)
            'Unlimited Token Issuance': 2.0,       # 무제한 발행 (중앙화 토큰에선 가능)
            'Sell-Path Block': 1.5,                # 매도 차단 (블랙리스트일 수도)

            # Administrative features (very low coefficient)
            'Contract Pause Abuse': 1.0,           # 컨트랙트 일시정지 (정상 기능일 수 있음)
            'Pausable Exit Block': 0.8,            # 일시정지로 인한 차단
            'Total Supply Manipulation': 0.5,      # 총 공급량 조작 (정상적일 수 있음)
            'Owner Pause Bypass': 0.3,             # 오너 우회 권한
            'Permanent Owner Control': 0.2,        # 영구 오너십 (일반적)
            'Execution Order Dependency': 0.1,     # 실행 순서 의존성 (일반적)
            'Missing Event': 0.1                   # 이벤트 누락 (코딩 실수)
        }

        # Base score starts at 100
        score = 100
        total_weighted_issues = 0

        for pattern_name, count in pattern_counts.items():
            if pattern_name in pattern_weights and count > 0:
                # Only check if pattern exists, ignore count
                weight = pattern_weights[pattern_name]
                total_weighted_issues += weight

        # Convert weighted issues to score deduction
        # More balanced scaling to allow proper differentiation
        if total_weighted_issues > 0:
            # Much gentler for low-weight administrative patterns
            if total_weighted_issues <= 5:  # Administrative features
                score_deduction = total_weighted_issues * 3
            elif total_weighted_issues <= 15: # Mixed patterns
                score_deduction = 15 + (total_weighted_issues - 5) * 2
            else: # High malicious patterns
                score_deduction = 35 + (total_weighted_issues - 15) * 3

            score_deduction = min(80, score_deduction)
            score = int(score - score_deduction)

        return max(0, score)

    def generate_result(self, input_data: Dict[str, Any], analysis_result: Union[Dict[str, Any], AnalysisReport],
                       source_hash: str) -> Dict[str, Any]:
        """Generate final JSON result"""
        if isinstance(analysis_result, AnalysisReport):
            # New format - use built-in risk scoring
            return analysis_result.to_dict()
        else:
            # Legacy format
            return {
                'category': 'STE',
                'analysis_score': self.calculate_risk_score(analysis_result),
                'source_hash': source_hash,
                'contract_name': input_data.get('ContractName', 'Unknown'),
                'analyzer_result': analysis_result
            }

    def process(self, input_file: str, use_new_architecture: bool = True) -> Dict[str, Any]:
        """
        Main processing function

        Args:
            input_file: Path to input JSON file
            use_new_architecture: Whether to use new unified architecture

        Returns:
            Analysis result dictionary
        """
        # Load input data
        input_data = self.load_input_data(input_file)

        # Check if input contains source code or bytecode
        source_code = input_data.get('SourceCode', '')
        bytecode = input_data.get('Bytecode', '')

        # Calculate hash (use source code if available, otherwise bytecode)
        content_for_hash = source_code if source_code else bytecode
        source_hash = self.calculate_source_hash(content_for_hash)

        if use_new_architecture:
            # Use new unified architecture
            if source_code and source_code.strip():
                # Use contract analyzer for source code
                processed_data = self.preprocess_data(input_data)
                contract_name = input_data.get('ContractName', 'Unknown')

                analysis_result = self.analyze(
                    processed_data['source_code'],
                    AnalysisType.SOURCE_CODE,
                    contract_name=contract_name
                )
            elif bytecode and bytecode.strip():
                # Use bytecode analyzer for bytecode
                contract_name = input_data.get('ContractName', 'Unknown')

                analysis_result = self.analyze(
                    bytecode,
                    AnalysisType.BYTECODE,
                    contract_name=contract_name
                )
            else:
                # No valid input found - create error report
                from common.types import AnalysisResult, AnalysisReport
                error_result = AnalysisResult(
                    pattern_name="Input Error",
                    findings=[],
                    error="No source code or bytecode found"
                )
                analysis_result = AnalysisReport(
                    analysis_type=AnalysisType.SOURCE_CODE,  # Default
                    target_hash=source_hash,
                    contract_name=input_data.get('ContractName', 'Unknown'),
                    results=[error_result]
                )

            return self.generate_result(input_data, analysis_result, source_hash)

        else:
            # Use legacy architecture for compatibility
            if source_code and source_code.strip():
                processed_data = self.preprocess_data(input_data)
                analysis_result = self.analyze_with_contract_analyzer(processed_data['source_code'])
                analysis_type = "source_code"
            elif bytecode and bytecode.strip():
                analysis_result = self.analyze_with_bytecode_analyzer(bytecode)
                analysis_type = "bytecode"
            else:
                analysis_result = {
                    "error": "No source code or bytecode found",
                    "summary": {"total_issues": 0, "pattern_counts": {}},
                    "findings": []
                }
                analysis_type = "none"

            result = self.generate_result(input_data, analysis_result, source_hash)
            result['analysis_type'] = analysis_type
            return result

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 processor.py <output.json>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)

    processor = TokenDataProcessor()
    try:
        # For now, use legacy mode to ensure patterns work
        result = processor.process(input_file, use_new_architecture=False)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Error processing data: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()