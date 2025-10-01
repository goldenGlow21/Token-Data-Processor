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

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        """Analyze contract code for STE0105 patterns"""
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