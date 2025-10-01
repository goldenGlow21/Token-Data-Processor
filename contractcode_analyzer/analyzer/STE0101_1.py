#!/usr/bin/env python3
"""
STE0101.1: Sell-Path Block / Conditional Revert
DEX Pair 전송/스왑 등 매도 경로에서만 revert 또는 실패 발생
"""

import re
from typing import List, Dict, Any


class STE0101_1_Analyzer:
    def __init__(self):
        self.name = "Sell-Path Block / Conditional Revert"
        self.description = "DEX Pair 전송/스왑 등 매도 경로에서만 revert 또는 실패 발생"
        self.weight = 1.0

        self.patterns = {
            "dex_revert": {
                "regex": r"(to|recipient|_to)\s*==\s*.*(pair|router|pool|dex|swap|pancake|uniswap|sushi).*\).*\{[\s\S]{0,100}?(revert|require\s*\(\s*false|return\s+false)",
                "score": 100,
                "description": "Direct revert when transferring to DEX"
            },
            "dex_conditional": {
                "regex": r"if\s*\(\s*(to|recipient|_to)\s*==\s*.*(pair|router|pool|dex).*\).*\{[\s\S]{0,200}?(require|revert|assert)",
                "score": 80,
                "description": "Conditional logic specifically for DEX addresses"
            },
            "asymmetric_transfer": {
                "regex": r"if\s*\(\s*(from|msg\.sender|_from)\s*==\s*.*(pair|router).*\)[\s\S]{0,50}?else\s+if\s*\(\s*(to|recipient|_to)\s*==\s*.*(pair|router)",
                "score": 70,
                "description": "Different logic for buy vs sell"
            },
            "sell_timing": {
                "regex": r"(sellCooldown|lastSell|_sellTime|sellInterval|antiDump).*require.*block\.(timestamp|number)",
                "score": 60,
                "description": "Time-based sell restrictions"
            },
            "trading_pause": {
                "regex": r"(tradingEnabled|tradingPaused|canTrade|tradingActive)\s*==\s*false.*require",
                "score": 50,
                "description": "Ability to pause trading"
            },
            "sell_limit": {
                "regex": r"if\s*\(\s*(to|recipient)\s*==.*pair.*\)[\s\S]{0,100}?require\(.*amount\s*<=\s*maxSell",
                "score": 40,
                "description": "Transaction limits specifically for sells"
            }
        }

        self.scoring_logic = {
            "method": "weighted_max",
            "decay_factor": 0.2
        }

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0101.1 patterns"""
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
            "ste_id": "STE0101_1",
            "name": self.name,
            "description": self.description,
            "score": final_score,
            "matches": matches
        }

    def _calculate_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate score based on matches and scoring logic"""
        if not matches:
            return 0.0

        method = self.scoring_logic.get("method", "weighted_max")

        if method == "weighted_max":
            # Take highest score with decay for additional matches
            sorted_matches = sorted(matches, key=lambda x: x["score"], reverse=True)
            decay_factor = self.scoring_logic.get("decay_factor", 0.2)

            score = 0
            for i, match in enumerate(sorted_matches):
                if i == 0:
                    score += match["score"]
                else:
                    score += match["score"] * decay_factor

            return min(100, score)

        # Default: take maximum
        return max(match["score"] for match in matches)