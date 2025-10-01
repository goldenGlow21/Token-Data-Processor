#!/usr/bin/env python3
"""
STE0104: Unlimited-Mint
민팅 권한으로 공급을 무제한 확대하고 시장 희석
"""

import re
from typing import List, Dict, Any


class STE0104_Analyzer:
    def __init__(self):
        self.name = "Unlimited-Mint"
        self.description = "민팅 권한으로 공급을 무제한 확대하고 시장 희석"
        self.weight = 1.0

        self.patterns = {
            "uncapped_mint": {
                "regex": r"function\s+(mint|_mint|issue)(?![\s\S]{0,200}?(maxSupply|MAX_SUPPLY|totalSupply\s*<=|totalSupply\s*\+.*<=))",
                "score": 100,
                "description": "Mint function with no maximum supply check"
            },
            "owner_mint_anytime": {
                "regex": r"function\s+mint.*onlyOwner.*\{[\s\S]{0,100}?(_mint|totalSupply\s*\+=|_balances\[.*\]\s*\+=)",
                "score": 90,
                "description": "Owner can mint tokens without restrictions"
            },
            "hidden_mint": {
                "regex": r"function\s+(?!mint|_mint|issue)[a-zA-Z_]+\s*\(.*uint.*\)[\s\S]{0,200}?totalSupply\s*\+=",
                "score": 85,
                "description": "Hidden function that increases supply"
            },
            "mutable_max_supply": {
                "regex": r"(maxSupply|MAX_SUPPLY|supplyCap)(?!.*constant|immutable).*=(?!.*constructor)",
                "score": 80,
                "description": "Maximum supply can be changed"
            },
            "multiple_mints": {
                "regex": r"function\s+mint[\s\S]{0,500}?function\s+(emergencyMint|adminMint|devMint)",
                "score": 75,
                "description": "Multiple minting mechanisms"
            },
            "mint_in_transfer": {
                "regex": r"function\s+(_transfer|transfer|transferFrom)[\s\S]{0,300}?totalSupply\s*\+=",
                "score": 70,
                "description": "Supply increases during transfers"
            },
            "rebase": {
                "regex": r"(rebase|Rebase|_rebase).*function.*totalSupply",
                "score": 60,
                "description": "Rebase mechanism that changes supply"
            },
            "no_burn": {
                "regex": r"function\s+mint(?![\s\S]*function\s+burn)",
                "score": 40,
                "description": "Mint exists but no burn function"
            }
        }

        self.scoring_logic = {
            "method": "severity_based",
            "multiplier_if_no_events": 1.2
        }

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0104 patterns"""
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
            "ste_id": "STE0104",
            "name": self.name,
            "description": self.description,
            "score": final_score,
            "matches": matches
        }

    def _calculate_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate score based on matches and scoring logic"""
        if not matches:
            return 0.0

        method = self.scoring_logic.get("method", "severity_based")

        if method == "severity_based":
            # Weight by severity and frequency
            score = max(match["score"] for match in matches)

            # Add bonus for multiple different patterns
            unique_patterns = len(set(match["pattern_name"] for match in matches))
            if unique_patterns > 1:
                multiplier = self.scoring_logic.get("multiplier_if_no_events", 1.0)
                score *= (1 + (unique_patterns - 1) * 0.1)  # 10% per additional pattern

            return min(100, score)

        # Default: take maximum
        return max(match["score"] for match in matches)