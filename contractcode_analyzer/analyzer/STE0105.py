#!/usr/bin/env python3
"""
STE0105: External Deposit Sink (ETH Push Trap)
ETH/Token을 넣게 유인하지만 출금은 owner만 가능
"""

import re
from typing import List, Dict, Any


class STE0105_Analyzer:
    def __init__(self):
        self.name = "External Deposit Sink"
        self.description = "ETH/Token을 넣게 유인하지만 출금은 owner만 가능"
        self.weight = 1.0

        self.patterns = {
            "eth_trap_no_withdraw": {
                "regex": r"(receive|fallback)\s*\(\s*\)\s*external\s+payable(?![\s\S]*function\s+(withdraw|claim|refund|retrieve))",
                "score": 100,
                "description": "Can receive ETH but no withdraw function"
            },
            "owner_only_withdraw": {
                "regex": r"function\s+(withdraw|claim|emergency|rescue).*onlyOwner[\s\S]{0,200}?(transfer|call\{value|send)",
                "score": 95,
                "description": "Only owner can withdraw funds"
            },
            "deposit_no_claim": {
                "regex": r"mapping\s*\(.*address.*uint.*\)\s*.*(deposit|balance|contribution)(?![\s\S]*function\s+(withdraw|claim).*msg\.sender)",
                "score": 90,
                "description": "Tracks deposits but no user withdrawal"
            },
            "investment_trap": {
                "regex": r"function\s+(invest|stake|deposit|contribute).*payable(?![\s\S]{0,500}?function\s+(unstake|withdraw).*msg\.sender)",
                "score": 85,
                "description": "Investment function without user withdrawal"
            },
            "asymmetric_conditions": {
                "regex": r"function\s+deposit.*\{[\s\S]{0,200}?function\s+withdraw.*require\(.*owner",
                "score": 80,
                "description": "Different conditions for deposit and withdraw"
            },
            "hidden_balance": {
                "regex": r"uint\s+private\s+.*balance|mapping.*private.*balance",
                "score": 70,
                "description": "Private balance tracking"
            },
            "no_refund": {
                "regex": r"payable(?![\s\S]*(refund|Refund|return.*value|msg\.sender\.transfer))",
                "score": 60,
                "description": "Accepts payments but no refund mechanism"
            },
            "misleading_names": {
                "regex": r"function\s+(claimReward|getRefund|withdrawProfit).*onlyOwner",
                "score": 50,
                "description": "Misleading function names with owner-only access"
            }
        }

        self.scoring_logic = {
            "method": "risk_weighted",
            "base_score": 30
        }

    def analyze(self, contract_code: str, original_code: str = None) -> Dict[str, Any]:
        """Analyze contract code for STE0105 patterns"""
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
            "ste_id": "STE0105",
            "name": self.name,
            "description": self.description,
            "score": final_score,
            "matches": matches
        }

    def _calculate_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate score based on matches and scoring logic"""
        if not matches:
            return 0.0

        method = self.scoring_logic.get("method", "risk_weighted")

        if method == "risk_weighted":
            # Start with base and weight by risk factors
            base = self.scoring_logic.get("base_score", 0)
            max_score = max((match["score"] for match in matches), default=0)

            # Weight by number of different risk patterns found
            risk_factor = len(set(match["pattern_name"] for match in matches))
            weighted_score = base + max_score * (1 + risk_factor * 0.1)

            return min(100, weighted_score)

        # Default: take maximum
        return max(match["score"] for match in matches)