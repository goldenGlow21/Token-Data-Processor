#!/usr/bin/env python3
"""
STE0103: Proxy-Upgrade Rug
Upgradable 프록시의 구현 로직 교체로 자금 탈출
"""

import re
from typing import List, Dict, Any


class STE0103_Analyzer:
    def __init__(self):
        self.name = "Proxy-Upgrade Rug"
        self.description = "Upgradable 프록시의 구현 로직 교체로 자금 탈출"
        self.weight = 1.0

        self.patterns = {
            "instant_upgrade": {
                "regex": r"function\s+(upgrade|setImplementation).*onlyOwner(?!.*timelock|delay|pending)",
                "score": 100,
                "description": "Owner can upgrade immediately without timelock"
            },
            "direct_implementation": {
                "regex": r"_implementation\s*=\s*.*(?!require.*timelock)",
                "score": 90,
                "description": "Direct implementation change without safeguards"
            },
            "proxy_selfdestruct": {
                "regex": r"(?:proxy|upgradeable|delegate)[\s\S]{0,500}?selfdestruct",
                "score": 85,
                "description": "Upgradeable proxy with selfdestruct"
            },
            "no_upgrade_event": {
                "regex": r"function\s+upgrade(?![\s\S]{0,200}?emit\s+Upgrad)",
                "score": 80,
                "description": "Upgrade function doesn't emit events"
            },
            "unchecked_delegatecall": {
                "regex": r"\.delegatecall\((?!.*require.*success)",
                "score": 75,
                "description": "Delegatecall without success check"
            },
            "multiple_upgrade_paths": {
                "regex": r"function\s+upgrade[\s\S]{0,500}?function\s+emergencyUpgrade",
                "score": 70,
                "description": "Multiple upgrade mechanisms"
            },
            "storage_collision": {
                "regex": r"assembly\s*\{[\s\S]{0,200}?sstore\(0x[0-9a-f]+",
                "score": 60,
                "description": "Direct storage manipulation in upgradeable"
            },
            "beacon_proxy": {
                "regex": r"(beacon|Beacon)\s+.*\s+(proxy|Proxy)",
                "score": 40,
                "description": "Beacon proxy pattern (centralized upgrades)"
            }
        }

        self.scoring_logic = {
            "method": "risk_accumulation",
            "base_score": 20,
            "max_score": 100
        }

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0103 patterns"""
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
            "ste_id": "STE0103",
            "name": self.name,
            "description": self.description,
            "score": final_score,
            "matches": matches
        }

    def _calculate_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate score based on matches and scoring logic"""
        if not matches:
            return 0.0

        method = self.scoring_logic.get("method", "risk_accumulation")

        if method == "risk_accumulation":
            # Start with base score and accumulate risks
            base = self.scoring_logic.get("base_score", 0)
            max_score = self.scoring_logic.get("max_score", 100)
            score = base

            # Add unique pattern scores with diminishing returns
            unique_scores = list(set(match["score"] for match in matches))
            for i, pattern_score in enumerate(sorted(unique_scores, reverse=True)):
                diminish = 1.0 / (i + 1)  # 1, 0.5, 0.33, ...
                score += pattern_score * diminish

            return min(max_score, score)

        # Default: take maximum
        return max(match["score"] for match in matches)