#!/usr/bin/env python3
"""
STE0101.2: High-Tax / Fee Bomb
거래시 과도한 세금(수수료)를 부과해 사실상 출구 봉쇄
"""

import re
from typing import List, Dict, Any


class STE0101_2_Analyzer:
    def __init__(self):
        self.name = "High-Tax / Fee Bomb"
        self.description = "거래시 과도한 세금(수수료)를 부과해 사실상 출구 봉쇄"
        self.weight = 1.0

        self.patterns = {
            "extreme_fee": {
                "regex": r"(fee|tax|commission)\s*[=>]\s*([5-9]\d|[1-9]\d{2,})(?!\s*\/\s*10000)",
                "score": 100,
                "description": "Fees above 50%"
            },
            "high_sell_fee": {
                "regex": r"(sellFee|sellTax|exitFee|liquidationFee)\s*[=>]\s*(2[5-9]|[3-9]\d|[1-9]\d{2,})",
                "score": 90,
                "description": "Sell fees above 25%"
            },
            "owner_fee_control": {
                "regex": r"function\s+set.*(Fee|Tax).*\(.*uint.*\).*(?:public|external).*(?:onlyOwner|admin|governance)",
                "score": 80,
                "description": "Owner can change fees arbitrarily"
            },
            "uncapped_fee": {
                "regex": r"(totalFee|sumFee|combinedFee).*\+.*(?!require.*<=\s*100)",
                "score": 75,
                "description": "No cap on total fees"
            },
            "asymmetric_fees": {
                "regex": r"(buyFee|buyTax)[\s\S]{0,100}?(sellFee|sellTax).*[!=]",
                "score": 60,
                "description": "Different fees for buying and selling"
            },
            "hidden_fees": {
                "regex": r"uint\s+private\s+.*(fee|tax)|_[a-z]{1,3}Fee\s*=\s*\d+",
                "score": 50,
                "description": "Obfuscated or hidden fee variables"
            },
            "multiple_fees": {
                "regex": r"(marketingFee.*liquidityFee.*devFee)|(teamFee.*burnFee.*reflectionFee)",
                "score": 40,
                "description": "Multiple stacking fee types"
            }
        }

        self.scoring_logic = {
            "method": "additive_capped",
            "base_threshold": 10
        }

    def analyze(self, contract_code: str, original_code: str = None) -> Dict[str, Any]:
        """Analyze contract code for STE0101.2 patterns"""
        matches = []

        # Use original code for line number calculation if provided
        code_for_line_numbers = original_code if original_code else contract_code

        # Find all pattern matches
        for pattern_name, pattern_config in self.patterns.items():
            regex_pattern = pattern_config["regex"]
            score = pattern_config["score"]
            description = pattern_config["description"]

            try:
                # Use multiline and case-insensitive flags
                flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

                for match in re.finditer(regex_pattern, contract_code, flags):
                    # Get matched text and position in preprocessed code
                    full_match = match.group(0)
                    match_start = match.start()
                    match_end = match.end()

                    # Include context before and after for unique matching
                    context_before = contract_code[max(0, match_start-30):match_start]
                    context_after = contract_code[match_end:min(len(contract_code), match_end+30)]
                    search_with_context = context_before + full_match[:100] + context_after

                    # Find in original code with context
                    original_match_pos = code_for_line_numbers.find(search_with_context)

                    if original_match_pos != -1:
                        # Adjust for the context_before length
                        actual_pos = original_match_pos + len(context_before)
                        text_before_match = code_for_line_numbers[:actual_pos]
                        line_number = text_before_match.count('\r\n') + 1

                        # Extract the full line(s) from original code for matched_text
                        line_start = code_for_line_numbers.rfind('\r\n', 0, actual_pos)
                        line_start = line_start + 2 if line_start != -1 else 0
                        line_end = code_for_line_numbers.find('\r\n', actual_pos)
                        line_end = line_end if line_end != -1 else len(code_for_line_numbers)
                        matched_text = code_for_line_numbers[line_start:line_end][:200]
                    else:
                        # Fallback: try without context
                        original_match_pos = code_for_line_numbers.find(full_match[:100])
                        if original_match_pos != -1:
                            text_before_match = code_for_line_numbers[:original_match_pos]
                            line_number = text_before_match.count('\r\n') + 1

                            # Extract the full line(s) from original code
                            line_start = code_for_line_numbers.rfind('\r\n', 0, original_match_pos)
                            line_start = line_start + 2 if line_start != -1 else 0
                            line_end = code_for_line_numbers.find('\r\n', original_match_pos)
                            line_end = line_end if line_end != -1 else len(code_for_line_numbers)
                            matched_text = code_for_line_numbers[line_start:line_end][:200]
                        else:
                            line_number = -1
                            matched_text = full_match[:200]

                    matches.append({
                        "pattern_name": pattern_name,
                        "score": score,
                        "description": description,
                        "matched_text": matched_text,
                        "line_number": line_number
                    })

            except re.error as e:
                print(f"Regex error in pattern {pattern_name}: {e}")

        # Calculate final score using scoring logic
        final_score = self._calculate_score(matches)

        return {
            "ste_id": "STE0101_2",
            "name": self.name,
            "description": self.description,
            "score": final_score,
            "matches": matches
        }

    def _calculate_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate score based on matches and scoring logic"""
        if not matches:
            return 0.0

        method = self.scoring_logic.get("method", "additive_capped")

        if method == "additive_capped":
            # Add all scores but cap at 100
            total = sum(match["score"] for match in matches)
            return min(100, total)

        # Default: take maximum
        return max(match["score"] for match in matches)