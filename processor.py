#!/usr/bin/env python3
"""
Main Token Analysis Processor
토큰 스캠 통합 분석 시스템

바이트코드와 소스코드를 모두 분석하여 종합 리포트를 생성합니다.
"""

import json
import time
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from bytecode_analyzer.bytecode_analyzer import BytecodeAnalyzer
from contractcode_analyzer.contract_code_analyzer import ContractCodeAnalyzer


class TokenAnalysisProcessor:
    """Main processor that coordinates bytecode and source code analysis"""

    def __init__(self):
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.contractcode_analyzer = ContractCodeAnalyzer()

    def analyze_from_json(self, json_file_path: str) -> Dict[str, Any]:
        """
        Analyze token from JSON file containing contract data

        Expected JSON format:
        {
            "contractName": "TokenName",
            "contractAddress": "0x...",
            "sourceCode": "contract ... { ... }",
            "bytecode": "0x..."
        }

        Args:
            json_file_path: Path to JSON file

        Returns:
            Complete analysis report
        """
        start_time = time.time()

        # Load JSON data
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Support multiple JSON formats
        contract_name = data.get('ContractName') or data.get('contractName', 'Unknown')
        contract_address = data.get('contractAddress', 'N/A')
        source_code = data.get('SourceCode') or data.get('sourceCode', '')
        bytecode = data.get('Bytecode') or data.get('bytecode', '')

        print(f"Analyzing contract: {contract_name} ({contract_address})")
        print("=" * 80)

        # Analyze source code
        print("Running source code analysis...")
        sourcecode_report = None
        if source_code:
            try:
                sourcecode_report = self.contractcode_analyzer.analyze(source_code, contract_name)
                print(f"✓ Source code analysis completed (Score: {sourcecode_report['overall_score']}/100)")
            except Exception as e:
                print(f"✗ Source code analysis failed: {e}")
                sourcecode_report = {"error": str(e)}
        else:
            print("⚠ No source code available")

        # Analyze bytecode
        print("Running bytecode analysis...")
        bytecode_report = None
        if bytecode:
            try:
                bytecode_report = self.bytecode_analyzer.analyze(bytecode, contract_name=contract_name)
                print(f"✓ Bytecode analysis completed")
            except Exception as e:
                print(f"✗ Bytecode analysis failed: {e}")
                bytecode_report = {"error": str(e)}
        else:
            print("⚠ No bytecode available")

        # Calculate overall risk assessment
        overall_assessment = self._calculate_overall_assessment(sourcecode_report, bytecode_report)

        # Build complete report
        total_time = time.time() - start_time

        complete_report = {
            "metadata": {
                "contract_name": contract_name,
                "contract_address": contract_address,
                "analysis_timestamp": time.time(),
                "total_execution_time": total_time
            },
            "source_code_analysis": sourcecode_report,
            "bytecode_analysis": bytecode_report,
            "overall_assessment": overall_assessment
        }

        print(f"\nTotal analysis time: {total_time:.3f}s")
        print("=" * 80)

        return complete_report

    def _calculate_overall_assessment(
        self,
        sourcecode_report: Optional[Dict[str, Any]],
        bytecode_report: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate overall risk assessment from both analyses"""

        # Get source code score
        source_score = 0
        if sourcecode_report and 'overall_score' in sourcecode_report:
            source_score = sourcecode_report['overall_score']

        # For now, bytecode analysis is structural only
        # We'll weight source code analysis more heavily
        final_score = source_score

        # Determine risk level
        if final_score >= 80:
            risk_level = "CRITICAL_RISK"
            verdict = "🚨 SCAM - DO NOT INVEST"
        elif final_score >= 60:
            risk_level = "VERY_HIGH_RISK"
            verdict = "⚠️ HIGHLY SUSPICIOUS - AVOID"
        elif final_score >= 40:
            risk_level = "HIGH_RISK"
            verdict = "⚠️ RISKY - PROCEED WITH CAUTION"
        elif final_score >= 20:
            risk_level = "MEDIUM_RISK"
            verdict = "ℹ️ SOME CONCERNS - INVESTIGATE FURTHER"
        else:
            risk_level = "LOW_RISK"
            verdict = "✓ APPEARS SAFE - STANDARD PATTERNS"

        assessment = {
            "final_score": round(final_score, 2),
            "risk_level": risk_level,
            "verdict": verdict,
            "recommendations": self._generate_recommendations(sourcecode_report)
        }

        return assessment

    def _generate_recommendations(self, sourcecode_report: Optional[Dict[str, Any]]) -> list:
        """Generate recommendations based on analysis results"""
        recommendations = []

        if not sourcecode_report or 'ste_results' not in sourcecode_report:
            return ["Unable to generate recommendations - analysis incomplete"]

        # Check each STE result
        for ste in sourcecode_report.get('ste_results', []):
            score = ste.get('score', 0)
            ste_id = ste.get('ste_id', '')

            if score >= 80:
                if 'STE0101' in ste_id:
                    recommendations.append("🚫 Exit restrictions detected - users may not be able to sell")
                elif 'STE0103' in ste_id:
                    recommendations.append("🚫 Upgradeable contract - owner can change logic at any time")
                elif 'STE0104' in ste_id:
                    recommendations.append("🚫 Unlimited minting capability - supply can be inflated")
                elif 'STE0105' in ste_id:
                    recommendations.append("🚫 Deposit trap detected - funds may be locked")

        if not recommendations:
            recommendations.append("✓ No critical scam patterns detected")
            recommendations.append("ℹ️ Always DYOR (Do Your Own Research)")

        return recommendations

    def save_report(self, report: Dict[str, Any], output_path: str) -> None:
        """Save analysis report to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Report saved to: {output_path}")

    def print_summary(self, report: Dict[str, Any]) -> None:
        """Print summary of analysis report"""
        print("\n" + "=" * 80)
        print("ANALYSIS SUMMARY")
        print("=" * 80)

        metadata = report.get('metadata', {})
        print(f"Contract: {metadata.get('contract_name', 'N/A')}")
        print(f"Address: {metadata.get('contract_address', 'N/A')}")
        print(f"Analysis Time: {metadata.get('total_execution_time', 0):.3f}s")
        print()

        assessment = report.get('overall_assessment', {})
        print(f"FINAL SCORE: {assessment.get('final_score', 0)}/100")
        print(f"RISK LEVEL: {assessment.get('risk_level', 'N/A')}")
        print(f"VERDICT: {assessment.get('verdict', 'N/A')}")
        print()

        print("RECOMMENDATIONS:")
        for rec in assessment.get('recommendations', []):
            print(f"  {rec}")

        print("=" * 80)

        # Print detailed source code analysis if available
        sourcecode_report = report.get('source_code_analysis')
        if sourcecode_report and 'ste_results' in sourcecode_report:
            print("\nDETAILED SOURCE CODE ANALYSIS:")
            self.contractcode_analyzer.print_report(sourcecode_report)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python main_processor.py <contract_data.json> [output.json]")
        print("\nExpected JSON format:")
        print('''{
  "contractName": "TokenName",
  "contractAddress": "0x...",
  "sourceCode": "contract ... { ... }",
  "bytecode": "0x..."
}''')
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Check if input file exists
    if not Path(input_file).exists():
        print(f"Error: File not found: {input_file}")
        sys.exit(1)

    # Run analysis
    processor = TokenAnalysisProcessor()
    report = processor.analyze_from_json(input_file)

    # Print summary
    processor.print_summary(report)

    # Save report
    if not output_file:
        # Create results directory if not exists
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)

        # Generate filename with contract name and timestamp
        contract_name = report['metadata'].get('contract_name', 'Unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = results_dir / f"{contract_name}_{timestamp}.json"

    processor.save_report(report, str(output_file))


if __name__ == "__main__":
    main()
