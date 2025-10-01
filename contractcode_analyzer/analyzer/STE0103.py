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

    def analyze(self, contract_code: str, original_code: str = None) -> Dict[str, Any]:
        """Analyze contract code for STE0103 patterns"""
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