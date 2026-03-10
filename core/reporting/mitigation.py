# core/reporting/mitigation.py
"""Generates specific mitigation recommendations for detected vulnerabilities."""
from __future__ import annotations
from typing import List

from core.vulnerability.models import PotentialVulnerability

# Known callback selectors (uniswap callbacks etc.) — ref: constants.py
_CALLBACK_SELECTORS = {
    bytes.fromhex("fa461e33"),  # uniswapV3SwapCallback
    bytes.fromhex("10d1e85c"),  # uniswapV3FlashCallback
    bytes.fromhex("e9cbafb0"),  # uniswapV3MintCallback
}


class MitigationGenerator:
    """Generate actionable mitigation recommendations for each vulnerability type."""

    def generate(self, vuln: PotentialVulnerability) -> List[str]:
        """
        Returns an ordered list of mitigation strings for the given vulnerability.
        Covers tx.origin misuse, controllable targets, controllable recipients,
        and DEX callback patterns.
        """
        mitigations: List[str] = []

        if vuln.requires_tx_origin_control:
            mitigations.append(
                "CRITICAL: Replace `tx.origin` checks with `msg.sender` checks. "
                "The `tx.origin` pattern is vulnerable to phishing attacks where "
                "an attacker lures the contract owner into interacting with a malicious contract."
            )

        if self._is_callback_pattern(vuln):
            mitigations.append(
                "For DEX callback functions (e.g., uniswapV3SwapCallback): "
                "Verify the caller is a legitimate pool using CREATE2 address derivation. "
                "See EIP-1014 for CREATE2 specification. "
                "Example: compute expected pool address from (factory, token0, token1, fee) "
                "and verify msg.sender matches."
            )

        if vuln.target_address.is_adversary_controllable:
            mitigations.append(
                "The token address passed to `transfer()` is entirely user-controlled. "
                "Maintain a whitelist of allowed token addresses, "
                "or verify that the token address matches expected internal state."
            )

        if vuln.recipient_arg.is_adversary_controllable:
            mitigations.append(
                "The transfer recipient is user-controlled with no authorization check. "
                "Ensure only the contract owner or pre-authorized addresses can trigger "
                "asset transfers, using storage-based access control rather than "
                "transaction-origin checks."
            )

        mitigations.append(
            "Note: Rigorous access control (e.g., CREATE2-based pool verification) "
            "consumes ~449 gas per check vs ~40 gas for simple tx.origin check. "
            "Evaluate the cost-security tradeoff for your use case."
        )

        return mitigations

    def _is_callback_pattern(self, vuln: PotentialVulnerability) -> bool:
        """
        Heuristic: a vulnerability that requires phishing and has a fixed risky
        selector that matches known DEX callback selectors is likely a callback pattern.
        """
        if not vuln.function_selector.is_risky_fixed:
            return False
        return vuln.requires_tx_origin_control
