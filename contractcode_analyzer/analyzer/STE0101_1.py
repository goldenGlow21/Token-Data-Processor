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

    def analyze(self, contract_code: str, original_code: str = None) -> Dict[str, Any]:
        """Analyze contract code for STE0101.1 patterns"""
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