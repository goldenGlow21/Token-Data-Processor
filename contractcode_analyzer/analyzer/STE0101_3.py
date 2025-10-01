#!/usr/bin/env python3
"""
STE0101.3: Blacklist / Whitelist-Gated
특정 주소만 전송 가능/불가하게 제한하는 로직
"""

import re
from typing import List, Dict, Any


class STE0101_3_Analyzer:
    def __init__(self):
        self.name = "Blacklist / Whitelist-Gated"
        self.description = "특정 주소만 전송 가능/불가하게 제한하는 로직"
        self.weight = 1.0

        self.patterns = {
            "permanent_blacklist": {
                "regex": r"mapping.*address.*bool.*blacklist(?![\s\S]*removeFromBlacklist)",
                "score": 100,
                "description": "Blacklist with no way to remove addresses"
            },
            "whitelist_only": {
                "regex": r"require\s*\(\s*(whitelist|allowlist|approved)\[.*\].*==.*true.*\).*_transfer",
                "score": 90,
                "description": "Only whitelisted addresses can transfer"
            },
            "owner_blacklist": {
                "regex": r"function\s+(blacklist|ban|block|restrict).*address.*onlyOwner",
                "score": 80,
                "description": "Owner can blacklist any address"
            },
            "bot_detection": {
                "regex": r"(isBot|_isBot|botList|antiBot).*mapping.*address.*bool.*require\s*\(!",
                "score": 70,
                "description": "Anti-bot mechanism that can block transfers"
            },
            "multiple_lists": {
                "regex": r"mapping.*blacklist[\s\S]{0,200}?mapping.*whitelist",
                "score": 60,
                "description": "Both blacklist and whitelist present"
            },
            "time_restrictions": {
                "regex": r"(lockedUntil|frozenUntil|restricted).*\[.*address.*\].*timestamp",
                "score": 40,
                "description": "Time-based transfer restrictions"
            }
        }

        self.scoring_logic = {
            "method": "weighted_max",
            "penalty_for_no_events": 20
        }

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0101.3 patterns"""
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
            "ste_id": "STE0101_3",
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
            # Take highest score
            max_score = max(match["score"] for match in matches)

            # Add penalty if configured
            penalty = self.scoring_logic.get("penalty_for_no_events", 0)
            # Note: This would require checking for events in the contract
            # For now, just return the max score

            return min(100, max_score)

        # Default: take maximum
        return max(match["score"] for match in matches)