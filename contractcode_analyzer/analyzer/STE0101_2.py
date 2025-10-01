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

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0101.2 patterns"""
        matches = []

        # Find all pattern matches
        for pattern_name, pattern_config in self.patterns.items():
            regex_pattern = pattern_config["regex"]
            score = pattern_config["score"]
            description = pattern_config["description"]

            try:
                # Use multiline and case-insensitive flags
                flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

                for match in re.finditer(regex_pattern, contract_code, flags):
                    # Calculate line number (handle both \n and \r\n)
                    text_before_match = contract_code[:match.start()]
                    line_number = text_before_match.count('\n') + text_before_match.count('\r\n') + 1

                    # Get matched text (limited)
                    matched_text = match.group(0)[:200]

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