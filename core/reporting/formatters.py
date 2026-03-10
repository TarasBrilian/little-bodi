# core/reporting/formatters.py
"""
JSON and Markdown report formatters for the ReportingEngine.
Consumes the full AnalysisContext to produce structured output.
"""
from __future__ import annotations
import json
import datetime
from typing import Any, Dict, List, Optional

from core.constants import TRACKED_TOKENS, TOKEN_DECIMALS, TOOL_VERSION
from core.pipeline import AnalysisContext
from core.vulnerability.models import PotentialVulnerability
from core.exploit_generation.models import Exploit
from core.validation.models import ValidatedExploit
from core.reporting.models import AnalysisSummary
from core.reporting.mitigation import MitigationGenerator


class JSONReportFormatter:
    """Builds the structured JSON report from the analysis context."""

    def __init__(self) -> None:
        self.mitigation_gen = MitigationGenerator()

    def format(self, ctx: AnalysisContext, summary: AnalysisSummary) -> Dict[str, Any]:
        """
        Build the full JSON report dict from the pipeline context.
        """
        end_time = ctx.analysis_end or datetime.datetime.now(datetime.timezone.utc)
        duration = (
            (end_time - ctx.analysis_start).total_seconds()
            if ctx.analysis_start
            else 0.0
        )


        vulns = ctx.potential_vulnerabilities or []
        exploits = ctx.exploits or []
        validated = ctx.validated_exploits or []

        # Build validated exploit lookup by PC
        validated_by_pc: Dict[int, ValidatedExploit] = {
            v.exploit.vuln_call_pc: v for v in validated
        }

        report: Dict[str, Any] = {
            "metadata": {
                "tool": "Little Bodi",
                "version": TOOL_VERSION,
                "paper_reference": "Yang et al., arXiv:2504.13398v3, 2025",
                "analysis_timestamp": ctx.analysis_start.isoformat() if ctx.analysis_start else "",
                "analysis_duration_seconds": round(duration, 2),
                "chain_id": ctx.chain_id,
            },
            "contract": {
                "address": ctx.contract_address or "",
                "bytecode_size_bytes": len(ctx.bytecode) if ctx.bytecode else 0,
                "block_analyzed": ctx.block_number,
            },
            "obfuscation": {
                "is_obfuscated": ctx.is_obfuscated,
                "indirect_jump_count": len(ctx.indirect_jumps),
                "coverage_before_percent": round(ctx.coverage_before, 2),
                "coverage_after_percent": round(ctx.coverage_after, 2),
                "branch_table_entry_count": len(ctx.indirect_jumps),
                "deobfuscation_successful": ctx.coverage_after > ctx.coverage_before,
            },
            "execution": {
                "mode": "concolic" if ctx.config.use_concolic else "symbolic",
                "seeds_extracted": len(ctx.seed_inputs),
                "paths_explored": len(ctx.execution_traces),
                "fell_back_to_symbolic": getattr(ctx, "fell_back_to_symbolic", False),
                "timeout_reached": False,
            },
            "vulnerabilities": [
                self._format_vuln(vuln, i + 1, exploits, validated_by_pc)
                for i, vuln in enumerate(vulns)
            ],
            "exploits": [
                self._format_exploit(exp, validated_by_pc)
                for exp in exploits
            ],
            "summary": {
                "total_vulnerabilities": summary.vulnerability_count,
                "confirmed_exploits": summary.confirmed_exploit_count,
                "total_estimated_loss_usd": round(summary.total_estimated_loss_usd, 2),
                "loss_is_lower_bound": True,
                "tokens_tracked": list(TRACKED_TOKENS.values()),
                "risk_level": summary.risk_level,
            },
        }
        return report

    def _format_vuln(
        self,
        vuln: PotentialVulnerability,
        idx: int,
        exploits: List[Exploit],
        validated: Dict[int, ValidatedExploit],
    ) -> Dict[str, Any]:
        mitigations = self.mitigation_gen.generate(vuln)
        has_exploit = any(e.vuln_call_pc == vuln.call_pc for e in exploits)
        is_validated = vuln.call_pc in validated and validated[vuln.call_pc].success

        subtype = (
            "fully_controllable_call"
            if vuln.target_address.is_adversary_controllable
            else "risky_fixed_selector"
        )

        return {
            "id": f"vuln-{idx:03d}",
            "call_pc": hex(vuln.call_pc),
            "confidence": round(vuln.confidence, 2),
            "type": "asset_management",
            "subtype": subtype,
            "requires_phishing": vuln.requires_tx_origin_control,
            "false_positive_candidate": vuln.false_positive_candidate,
            "false_positive_reason": vuln.false_positive_reason,
            "target_address": {
                "adversary_controllable": vuln.target_address.is_adversary_controllable,
                "is_risky_fixed": vuln.target_address.is_risky_fixed,
                "calldata_bytes": vuln.target_address.tainted_bytes,
            },
            "function_selector": {
                "adversary_controllable": vuln.function_selector.is_adversary_controllable,
                "is_risky_fixed": vuln.function_selector.is_risky_fixed,
                "decoded": "transfer(address,uint256)" if vuln.function_selector.is_risky_fixed else "unknown",
            },
            "recipient": {
                "adversary_controllable": vuln.recipient_arg.is_adversary_controllable,
                "calldata_bytes": vuln.recipient_arg.tainted_bytes,
            },
            "amount": {
                "adversary_controllable": vuln.amount_arg.is_adversary_controllable,
                "calldata_bytes": vuln.amount_arg.tainted_bytes,
            },
            "exploit_generated": has_exploit,
            "exploit_validated": is_validated,
            "mitigation": " ".join(mitigations),
        }

    def _format_exploit(
        self,
        exp: Exploit,
        validated: Dict[int, ValidatedExploit],
    ) -> Dict[str, Any]:
        v = validated.get(exp.vuln_call_pc)
        validation_result = {
            "success": v.success if v else False,
            "gas_used": v.tx_receipt.get("gas_used", 0) if (v and v.tx_receipt) else 0,
            "validation_note": v.validation_note if v else None,
            "transfer_events": len(v.transfer_events) if v else 0,
            "estimated_loss_usd": round(v.estimated_loss_usd, 2) if v else 0.0,
            "validation_error": v.validation_error if v else "Not validated",
        }
        return {
            "vulnerability_id": hex(exp.vuln_call_pc),
            "token": exp.target_token_symbol,
            "from_address": exp.from_address,
            "to_address": exp.to_address,
            "calldata_hex": "0x" + exp.calldata.hex(),
            "value_wei": exp.value,
            "block_number": exp.block_number,
            "validation_result": validation_result,
        }


class MarkdownReportFormatter:
    """Generates the human-readable Markdown report."""

    _TEMPLATE = """\
# Little Bodi Analysis Report

**Contract**: `{contract_address}`
**Analyzed at block**: {block_number}
**Analysis duration**: {duration:.1f}s
**Date**: {timestamp}

---

## Obfuscation Analysis

| Metric | Value |
|--------|-------|
| Obfuscated | {is_obfuscated} |
| Code coverage (before) | {coverage_before:.1f}% |
| Code coverage (after) | {coverage_after:.1f}% |
| Indirect jumps found | {indirect_jump_count} |
| Branch table entries | {branch_table_entries} |

{deobfuscation_status}

---

## Symbolic Path Analysis (Bypass Mode: {bypass_mode})

{cfg_visualization}

---

## Vulnerability Summary

{vulnerability_count} vulnerability/vulnerabilities found.

{vulnerability_details}

---

## Exploit Summary

{exploit_summary}

---

## Estimated Financial Impact

**Total Potential Exposure**: ${total_potential_loss_usd:,.2f}
**Total Confirmed Loss**: ${total_validated_loss_usd:,.2f}

> Note: **Total Potential Exposure** reflects assets at risk if internal access controls (whitelists/owners) are compromised. This is the value an attacker would target in a phishing or private key compromise scenario.

---

## Mitigations

{mitigation_list}

---

## Technical Details

*For full technical details, see the accompanying JSON report.*

---

*Generated by Little Bodi — based on SKANF methodology (Yang et al., arXiv:2504.13398v3, 2025)*
"""

    def __init__(self) -> None:
        self.mitigation_gen = MitigationGenerator()

    def format(self, ctx: AnalysisContext, summary: AnalysisSummary) -> str:
        """
        Renders the Markdown report string from the analysis context and summary.
        """
        duration = (
            (ctx.analysis_end - ctx.analysis_start).total_seconds()
            if ctx.analysis_end and ctx.analysis_start
            else 0.0
        )
        timestamp = (
            ctx.analysis_start.strftime("%Y-%m-%d %Human:%M:%S UTC")
            if ctx.analysis_start
            else "N/A"
        )
        timestamp = (
            ctx.analysis_start.strftime("%Y-%m-%d %H:%M:%S UTC")
            if ctx.analysis_start
            else "N/A"
        )

        vulns = ctx.potential_vulnerabilities or []
        exploits = ctx.exploits or []
        validated = ctx.validated_exploits or []

        deobf_status = (
            "> Deobfuscation successful — coverage restored from "
            f"{ctx.coverage_before:.1f}% to {ctx.coverage_after:.1f}%."
            if ctx.is_obfuscated and ctx.coverage_after > ctx.coverage_before
            else "> No obfuscation detected."
        )

        bypass_mode = "ENABLED (Whitebox)" if ctx.config.bypass_access_control else "DISABLED (Standard)"
        cfg_visualization = self._render_cfg_visualization(ctx)
        vuln_details = self._render_vuln_details(vulns)
        exploit_summary = self._render_exploit_summary(exploits, validated)
        mitigation_list = self._render_mitigations(vulns)

        total_potential_loss = sum(e.estimated_loss_usd for e in exploits)
        total_validated_loss = summary.total_estimated_loss_usd
        token_list = ", ".join(TRACKED_TOKENS.values())
        token_count = len(TRACKED_TOKENS)

        return self._TEMPLATE.format(
            contract_address=ctx.contract_address or "unknown",
            block_number=ctx.block_number or "latest",
            duration=duration,
            timestamp=timestamp,
            is_obfuscated=str(ctx.is_obfuscated),
            coverage_before=ctx.coverage_before,
            coverage_after=ctx.coverage_after,
            indirect_jump_count=len(ctx.indirect_jumps),
            branch_table_entries=len(ctx.indirect_jumps),
            deobfuscation_status=deobf_status,
            bypass_mode=bypass_mode,
            cfg_visualization=cfg_visualization,
            vulnerability_count=len(vulns),
            vulnerability_details=vuln_details or "_No vulnerabilities detected._",
            exploit_summary=exploit_summary or "_No exploits generated._",
            total_potential_loss_usd=total_potential_loss,
            total_validated_loss_usd=total_validated_loss,
            mitigation_list=mitigation_list or "_No mitigations required._",
        )

    def _render_cfg_visualization(self, ctx: AnalysisContext) -> str:
        """Generates a Mermaid CFG diagram showing the bypass and vulnerable sink."""
        if not ctx.potential_vulnerabilities:
            return "_No vulnerable paths to visualize._"

        # Simplified Mermaid visualization
        mermaid = ["```mermaid", "graph TD"]
        mermaid.append("  Start[Entry Point] --> Check{Owner Check}")
        mermaid.append("  Check -->|Normal User| Revert[REVERT / INVALID]")
        
        if ctx.config.bypass_access_control:
            mermaid.append("  Check -->|Whitebox Bypass| Logic[Contract Logic]")
            for i, v in enumerate(ctx.potential_vulnerabilities, 1):
                mermaid.append(f"  Logic --> Vuln{i}[vuln-{i:03d} at {hex(v.call_pc)}]")
                mermaid.append(f"  Vuln{i} --> Sink[Vulnerable CALL / Transfer]")
        else:
            mermaid.append("  Check -->|Owner Only| Logic[logic obscured]")
            
        mermaid.append("```")
        return "\n".join(mermaid)

    def _render_vuln_details(self, vulns: List[PotentialVulnerability]) -> str:
        parts = []
        for i, v in enumerate(vulns, 1):
            confidence_pct = int(v.confidence * 100)
            phish = " *(requires phishing)*" if v.requires_tx_origin_control else ""
            parts.append(
                f"### vuln-{i:03d} @ PC `{hex(v.call_pc)}`\n"
                f"- **Type**: asset_management{phish}\n"
                f"- **Confidence**: {confidence_pct}%\n"
                f"- **Is False Positive Candidate**: {v.false_positive_candidate}\n"
                f"- **Reason**: {v.false_positive_reason or 'N/A'}\n"
                f"- **Recipient controllable**: {v.recipient_arg.is_adversary_controllable}\n"
                f"- **Target controllable**: {v.target_address.is_adversary_controllable}\n"
            )
        return "\n".join(parts)

    def _render_exploit_summary(
        self,
        exploits: List[Exploit],
        validated: List[ValidatedExploit],
    ) -> str:
        if not exploits:
            return ""
        validated_map = {v.exploit.vuln_call_pc: v for v in validated}
        rows = [
            "| # | Token | Validated | Status | Potential Exposure |",
            "|---|-------|-----------|--------|-------------------|"
        ]
        for i, exp in enumerate(exploits, 1):
            v = validated_map.get(exp.vuln_call_pc)
            ok = "**YES**" if (v and v.success) else "No"
            
            # Use potential loss from the individual exploit if validated loss is 0
            loss_val = exp.estimated_loss_usd or 0.0
            
            if loss_val > 0:
                loss_str = f"${loss_val:,.2f}"
            else:
                loss_str = "-"
            
            status = "_N/A_"
            if v:
                if v.success:
                    status = "**Confirmed**"
                elif v.validation_note:
                    # Simplify the status string for the jury
                    status = "Access Control Blocked" if "access control" in v.validation_note.lower() else v.validation_note
                else:
                    status = "_Reverted_"
            
            rows.append(f"| {i} | {exp.target_token_symbol} | {ok} | {status} | {loss_str} |")
        return "\n".join(rows)

    def _render_mitigations(self, vulns: List[PotentialVulnerability]) -> str:
        all_points = []
        for i, v in enumerate(vulns, 1):
            mits = self.mitigation_gen.generate(v)
            all_points.append(f"**vuln-{i:03d}**:")
            for m in mits:
                all_points.append(f"- {m}")
        return "\n".join(all_points)
