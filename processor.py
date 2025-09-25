#!/usr/bin/env python3
import json
import sys
import hashlib
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any

class TokenDataProcessor:
    def __init__(self):
        self.contract_analyzer_path = Path("../contractCodeAnalyzer")

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

    def analyze_with_contract_analyzer(self, source_code: str) -> Dict[str, Any]:
        """Run contract code analysis using the external analyzer"""
        try:
            # Import and use the contract analyzer directly
            import sys
            sys.path.append(str(self.contract_analyzer_path))
            from contract_analyzer import ContractAnalyzer

            analyzer = ContractAnalyzer()
            analysis_result = analyzer.analyze_contract(source_code)

            return analysis_result

        except Exception as e:
            return {"error": str(e), "total_findings": 0, "findings_by_category": {}, "detailed_findings": []}

    def detect_ste_issues(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect STE (Security Token Exchange) related issues"""
        source_code = processed_data['source_code']
        issues = []
        score = 100

        # Basic STE detection patterns
        ste_patterns = {
            'unlimited_mint': ['mint(', '_mint(', 'totalSupply'],
            'exit_restriction': ['transfer(', 'transferFrom(', 'approve('],
            'owner_privileges': ['onlyOwner', 'owner', 'admin'],
            'pausable_functions': ['pause(', 'unpause(', '_pause'],
            'blacklist_functionality': ['blacklist', 'blocked', 'banned']
        }

        detection_counts = {}

        for category, patterns in ste_patterns.items():
            count = 0
            for pattern in patterns:
                count += source_code.count(pattern)

            detection_counts[category] = count

            # Scoring logic
            if category == 'unlimited_mint' and count > 5:
                score -= 20
            elif category == 'owner_privileges' and count > 10:
                score -= 15
            elif category == 'blacklist_functionality' and count > 0:
                score -= 10

        return {
            'detection_counts': detection_counts,
            'issues': issues,
            'score': max(0, score)
        }

    def generate_result(self, input_data: Dict[str, Any], analysis_result: Dict[str, Any],
                       ste_result: Dict[str, Any], source_hash: str) -> Dict[str, Any]:
        """Generate final JSON result"""
        return {
            'category': 'STE',
            'source_analysis': {
                'detection_items': ste_result['detection_counts'],
                'total_detections': sum(ste_result['detection_counts'].values())
            },
            'analysis_score': ste_result['score'],
            'source_hash': source_hash,
            'contract_name': input_data.get('ContractName', 'Unknown'),
            'analyzer_result': analysis_result
        }

    def process(self, input_file: str) -> Dict[str, Any]:
        """Main processing function"""
        # Load input data
        input_data = self.load_input_data(input_file)

        # Calculate source code hash
        source_hash = self.calculate_source_hash(input_data.get('SourceCode', ''))

        # Preprocess data
        processed_data = self.preprocess_data(input_data)

        # Analyze with contract code analyzer
        analysis_result = self.analyze_with_contract_analyzer(processed_data['source_code'])

        # Detect STE issues
        ste_result = self.detect_ste_issues(processed_data)

        # Generate final result
        return self.generate_result(input_data, analysis_result, ste_result, source_hash)

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
        result = processor.process(input_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Error processing data: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()