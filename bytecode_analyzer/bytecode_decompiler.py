#!/usr/bin/env python3
"""
Ethereum Bytecode Decompiler
바이트코드를 디컴파일하여 .sol 파일로 변환합니다.
"""

import sys
import os
import re
import json
from typing import Dict, List, Tuple, Optional

class BytecodeDecompiler:
    def __init__(self, signatures_dir: str = "signatures"):
        self.signatures_dir = signatures_dir
        self.function_signatures = {}
        self.load_signatures()

    def load_signatures(self):
        """시그니처 파일들을 로드하여 메모리에 저장"""
        if not os.path.exists(self.signatures_dir):
            print(f"Warning: Signatures directory '{self.signatures_dir}' not found")
            return

        print(f"Loading function signatures from {self.signatures_dir}...")
        print("Note: Initial load will analyze bytecode first, then load only needed signatures")

        # 먼저 빈 딕셔너리로 시작 (필요할 때만 로드)
        self.function_signatures = {}

        print("Signatures will be loaded on-demand during analysis")

    def load_signature_for_selector(self, selector: str) -> str:
        """특정 선택자에 대한 시그니처를 로드"""
        if selector in self.function_signatures:
            return self.function_signatures[selector]

        # 시그니처 파일에서 로드 시도
        filepath = os.path.join(self.signatures_dir, selector)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    signature = f.read().strip()
                    if signature:
                        self.function_signatures[selector] = signature
                        return signature
            except Exception as e:
                print(f"Warning: Failed to load signature for {selector}: {e}")

        return None

    def extract_function_selectors(self, bytecode: str) -> List[str]:
        """바이트코드에서 함수 선택자를 추출"""
        selectors = []
        # EQ (14) 명령어 앞의 4바이트 값들을 찾아 함수 선택자로 간주
        bytecode = bytecode.replace('0x', '').lower()

        # PUSH4 (63) 명령어 뒤의 4바이트를 찾기
        i = 0
        while i < len(bytecode) - 8:
            if bytecode[i:i+2] == '63':  # PUSH4
                selector = bytecode[i+2:i+10]
                if len(selector) == 8:
                    selectors.append(selector)
                i += 10
            else:
                i += 2

        return list(set(selectors))  # 중복 제거

    def resolve_function_name(self, selector: str) -> str:
        """함수 선택자를 함수 시그니처로 변환"""
        # 캐시에서 먼저 확인
        if selector in self.function_signatures:
            return self.function_signatures[selector]

        # 시그니처 파일에서 로드 시도
        signature = self.load_signature_for_selector(selector)
        if signature:
            return signature

        return f"unknown_{selector}"

    def analyze_bytecode_structure(self, bytecode: str) -> Dict:
        """바이트코드 구조 분석"""
        bytecode = bytecode.replace('0x', '').lower()

        # 기본 구조 정보
        structure = {
            'constructor': None,
            'functions': [],
            'events': [],
            'modifiers': [],
            'storage_vars': []
        }

        # 함수 선택자 추출
        selectors = self.extract_function_selectors(bytecode)

        for selector in selectors:
            function_sig = self.resolve_function_name(selector)

            # 함수 정보 파싱
            function_info = self.parse_function_signature(function_sig, selector)
            structure['functions'].append(function_info)

        return structure

    def parse_function_signature(self, signature: str, selector: str) -> Dict:
        """함수 시그니처를 파싱하여 구조화된 정보 반환"""
        # 기본 함수 정보
        function_info = {
            'selector': selector,
            'signature': signature,
            'name': 'unknown',
            'inputs': [],
            'outputs': [],
            'visibility': 'public',
            'mutability': 'nonpayable'
        }

        if signature.startswith('unknown_'):
            function_info['name'] = signature
            return function_info

        # 함수명과 파라미터 분리
        match = re.match(r'([^(]+)\(([^)]*)\)', signature)
        if match:
            function_info['name'] = match.group(1).strip()
            params_str = match.group(2).strip()

            if params_str:
                # 파라미터 파싱 (중첩된 구조체 고려)
                params = self.parse_parameters(params_str)
                function_info['inputs'] = params

        return function_info

    def parse_parameters(self, params_str: str) -> List[Dict]:
        """함수 파라미터를 파싱"""
        if not params_str:
            return []

        params = []
        # 간단한 파라미터 분리 (향후 개선 필요)
        param_parts = params_str.split(',')

        for i, part in enumerate(param_parts):
            part = part.strip()
            if part:
                params.append({
                    'type': part,
                    'name': f'param{i}',
                    'internalType': part
                })

        return params

    def generate_solidity_code(self, structure: Dict, contract_name: str) -> str:
        """구조화된 정보를 바탕으로 Solidity 코드 생성"""
        solidity_code = []

        # SPDX 라이센스와 pragma
        solidity_code.append("// SPDX-License-Identifier: MIT")
        solidity_code.append("pragma solidity ^0.8.0;")
        solidity_code.append("")

        # 컨트랙트 선언
        solidity_code.append(f"contract {contract_name} {{")
        solidity_code.append("")

        # 상태 변수 (기본적인 것들 추가)
        if structure['storage_vars']:
            solidity_code.append("    // State Variables")
            for var in structure['storage_vars']:
                solidity_code.append(f"    {var};")
            solidity_code.append("")

        # 이벤트
        if structure['events']:
            solidity_code.append("    // Events")
            for event in structure['events']:
                solidity_code.append(f"    {event};")
            solidity_code.append("")

        # 함수들
        if structure['functions']:
            solidity_code.append("    // Functions")
            for func in structure['functions']:
                func_code = self.generate_function_code(func)
                solidity_code.append(func_code)
                solidity_code.append("")

        solidity_code.append("}")

        return "\n".join(solidity_code)

    def generate_function_code(self, func_info: Dict) -> str:
        """개별 함수 코드 생성"""
        name = func_info['name']
        inputs = func_info['inputs']
        visibility = func_info['visibility']
        mutability = func_info['mutability']

        # 파라미터 문자열 생성
        if inputs:
            params = []
            for param in inputs:
                params.append(f"{param['type']} {param['name']}")
            params_str = ", ".join(params)
        else:
            params_str = ""

        # 함수 시그니처 생성
        func_signature = f"    function {name}({params_str}) {visibility}"

        if mutability != 'nonpayable':
            func_signature += f" {mutability}"

        # 리턴 타입이 있다면 추가 (현재는 기본으로 비워둠)
        func_signature += " {"

        # 함수 본문 (기본 구현)
        func_body = [
            func_signature,
            f"        // Function selector: 0x{func_info['selector']}",
            f"        // Original signature: {func_info['signature']}",
            "        // TODO: Implement function logic",
            "        revert(\"Not implemented\");",
            "    }"
        ]

        return "\n".join(func_body)

    def generate_function_summary(self, structure: Dict) -> Dict:
        """함수 정보를 JSON으로 반환하기 위한 요약 생성"""
        summary = {
            "total_functions": len(structure['functions']),
            "all_functions": [func['name'] for func in structure['functions']],
            "contract_info": {
                "has_constructor": structure['constructor'] is not None,
                "event_count": len(structure['events']),
                "modifier_count": len(structure['modifiers'])
            },
            "functions": []
        }

        for func in structure['functions']:
            func_summary = {
                "name": func['name'],
                "selector": f"0x{func['selector']}",
                "signature": func['signature'],
                "visibility": func['visibility'],
                "mutability": func['mutability'],
                "input_count": len(func['inputs']),
                "inputs": func['inputs'],
                "description": self.generate_function_description(func)
            }
            summary['functions'].append(func_summary)

        return summary

    def generate_function_description(self, func_info: Dict) -> str:
        """함수에 대한 간단한 설명 생성"""
        name = func_info['name']
        input_count = len(func_info['inputs'])

        if name.startswith('unknown_'):
            return f"Unknown function with selector {func_info['selector']}"

        # 일반적인 함수명 패턴 분석
        description_parts = []

        # 함수 타입 추정
        if name in ['transfer', 'transferFrom']:
            description_parts.append("Token transfer function")
        elif name in ['approve', 'allowance']:
            description_parts.append("Token approval function")
        elif name in ['balanceOf', 'totalSupply']:
            description_parts.append("Token balance query function")
        elif name.startswith('get') or name.startswith('view'):
            description_parts.append("Read-only function")
        elif name.startswith('set') or name.startswith('update'):
            description_parts.append("State modification function")
        elif name == 'owner' or name == 'admin':
            description_parts.append("Access control function")
        else:
            description_parts.append("Contract function")

        if input_count > 0:
            description_parts.append(f"with {input_count} parameter(s)")
        else:
            description_parts.append("with no parameters")

        return " ".join(description_parts)


    def decompile(self, bytecode: str, output_filename: str):
        """바이트코드를 디컴파일하여 .sol 파일로 저장"""
        print(f"Decompiling bytecode to {output_filename}...")

        # 바이트코드 구조 분석
        structure = self.analyze_bytecode_structure(bytecode)

        # 컨트랙트 이름 추출 (파일명에서)
        contract_name = os.path.splitext(os.path.basename(output_filename))[0]
        contract_name = contract_name.replace('-', '_').replace(' ', '_')
        if not contract_name[0].isalpha():
            contract_name = 'Contract_' + contract_name

        # Solidity 코드 생성
        solidity_code = self.generate_solidity_code(structure, contract_name)

        # .sol 파일로 저장
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(solidity_code)

        # JSON 요약 생성하여 반환
        summary = self.generate_function_summary(structure)
        return summary

def main():
    if len(sys.argv) != 3:
        print("Usage: python bytecode_decompiler.py <bytecode_file> <output.sol>")
        print("Example: python bytecode_decompiler.py Zhonghua.txt MyContract.sol")
        sys.exit(1)

    bytecode_file = sys.argv[1]
    output_file = sys.argv[2]

    # 바이트코드 파일에서 읽기
    try:
        with open(bytecode_file, 'r', encoding='utf-8') as f:
            bytecode = f.read().strip()
    except FileNotFoundError:
        print(f"Error: Bytecode file '{bytecode_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading bytecode file: {e}")
        sys.exit(1)

    if not bytecode:
        print("Error: Bytecode file is empty")
        sys.exit(1)

    # .sol 확장자 확인
    if not output_file.endswith('.sol'):
        output_file += '.sol'

    # 디컴파일러 실행
    decompiler = BytecodeDecompiler()
    summary = decompiler.decompile(bytecode, output_file)

    # JSON 결과 출력
    print(json.dumps(summary, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()