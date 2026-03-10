# core/reporting/engine.py
"""
ReportingEngine: Generates structured JSON and Markdown analysis reports
from the complete pipeline results.
"""
from __future__ import annotations
import json
import logging
import os
import datetime
from typing import List, Optional

from core.pipeline import BaseEngine, AnalysisContext, AnalysisConfig
from core.vulnerability.models import PotentialVulnerability
from core.reporting.models import AnalysisSummary, ReportFiles
from core.reporting.formatters import JSONReportFormatter, MarkdownReportFormatter

logger = logging.getLogger(__name__)


class CLIReporter:
    """
    Prints a styled terminal summary of the analysis.
    Uses `rich` if available, falls back to plain text.
    """

    def print_summary(self, summary: AnalysisSummary) -> None:
        """Print the analysis summary to stdout."""
        try:
            from rich.console import Console
            from rich.panel import Panel

            console = Console()
            risk_colors = {
                "none": "green",
                "low": "yellow",
                "medium": "orange3",
                "high": "red",
                "critical": "bold red",
            }
            color = risk_colors.get(summary.risk_level, "white")
            console.print(Panel(
                f"[bold]Little Bodi Analysis Complete[/bold]\n"
                f"Contract: {summary.contract_address}\n"
                f"Risk Level: [{color}]{summary.risk_level.upper()}[/]\n"
                f"Vulnerabilities: {summary.vulnerability_count}\n"
                f"Confirmed Exploits: {summary.confirmed_exploit_count}\n"
                f"Estimated Loss: ${summary.total_estimated_loss_usd:,.0f} (lower bound)\n"
                f"Duration: {summary.analysis_duration_seconds:.1f}s",
                title="Analysis Result",
                border_style=color,
            ))
        except ImportError:
            # Plain-text fallback when rich is not installed
            print("=" * 60)
            print(f"  Little Bodi Analysis Complete")
            print(f"  Contract:      {summary.contract_address}")
            print(f"  Risk Level:    {summary.risk_level.upper()}")
            print(f"  Vulns:         {summary.vulnerability_count}")
            print(f"  Exploits:      {summary.confirmed_exploit_count}")
            print(f"  Loss (est.):   ${summary.total_estimated_loss_usd:,.0f}")
            print(f"  Duration:      {summary.analysis_duration_seconds:.1f}s")
            print("=" * 60)


class ReportingEngine(BaseEngine):
    """
    Final stage of the pipeline: writes JSON and Markdown reports to disk
    and prints a CLI summary. Does not raise on missing exploits/vulns —
    a clean report is always valid output.
    """

    def __init__(self, config: AnalysisConfig) -> None:
        super().__init__(config)
        self.json_formatter = JSONReportFormatter()
        self.md_formatter = MarkdownReportFormatter()
        self.cli_reporter = CLIReporter()

    def validate_input(self, ctx: AnalysisContext) -> None:
        """No strict validation — reporting works even on clean contracts."""
        pass

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        Builds the analysis summary, writes reports to disk,
        and prints the CLI summary. Attaches the summary to ctx.
        """
        summary = self._build_summary(ctx)
        output_dir = self.config.output_dir
        os.makedirs(output_dir, exist_ok=True)

        report_files: List[str] = []

        if "json" in self.config.report_formats:
            path = self._write_json(ctx, summary, output_dir)
            report_files.append(path)

        if "markdown" in self.config.report_formats:
            path = self._write_markdown(ctx, summary, output_dir)
            report_files.append(path)

        self.cli_reporter.print_summary(summary)

        logger.info(f"Reports written: {report_files}")
        ctx.report_files = report_files
        ctx.analysis_summary = summary
        return ctx

    def _build_summary(self, ctx: AnalysisContext) -> AnalysisSummary:
        """Aggregates pipeline results into an AnalysisSummary."""
        vulns = ctx.potential_vulnerabilities or []
        validated = ctx.validated_exploits or []

        confirmed = sum(1 for v in validated if v.success)
        total_loss = sum(v.estimated_loss_usd for v in validated if v.success)

        duration = (
            (ctx.analysis_end - ctx.analysis_start).total_seconds()
            if ctx.analysis_end and ctx.analysis_start
            else 0.0
        )

        return AnalysisSummary(
            contract_address=ctx.contract_address or "unknown",
            is_vulnerable=len(vulns) > 0,
            vulnerability_count=len(vulns),
            confirmed_exploit_count=confirmed,
            total_estimated_loss_usd=total_loss,
            obfuscation_detected=ctx.is_obfuscated,
            coverage_improvement=max(0.0, ctx.coverage_after - ctx.coverage_before),
            analysis_duration_seconds=round(duration, 2),
            mode_used="concolic" if ctx.config.use_concolic else "symbolic",
        )

    def _write_json(
        self, ctx: AnalysisContext, summary: AnalysisSummary, output_dir: str
    ) -> str:
        """Serialise the report to a JSON file and return its path."""
        report = self.json_formatter.format(ctx, summary)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        addr = (ctx.contract_address or "unknown").replace("0x", "")[:8]
        filename = f"report_{addr}_{timestamp}.json"
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return path

    def _write_markdown(
        self, ctx: AnalysisContext, summary: AnalysisSummary, output_dir: str
    ) -> str:
        """Render the Markdown report and return its path."""
        md = self.md_formatter.format(ctx, summary)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        addr = (ctx.contract_address or "unknown").replace("0x", "")[:8]
        filename = f"report_{addr}_{timestamp}.md"
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path
