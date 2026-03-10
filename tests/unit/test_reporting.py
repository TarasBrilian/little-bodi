# tests/unit/test_reporting.py
"""
Unit tests for the ReportingEngine.
"""
import json
import os
import tempfile
import datetime
import pytest

from core.reporting.engine import ReportingEngine, CLIReporter
from core.reporting.formatters import JSONReportFormatter, MarkdownReportFormatter
from core.reporting.mitigation import MitigationGenerator
from core.reporting.models import AnalysisSummary
from core.vulnerability.models import PotentialVulnerability, VulnCallParam
from core.exploit_generation.models import Exploit
from core.validation.models import ValidatedExploit
from core.pipeline import AnalysisContext, AnalysisConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(
    *,
    requires_phishing: bool = False,
    target_ctrl: bool = False,
    recipient_ctrl: bool = True,
) -> PotentialVulnerability:
    return PotentialVulnerability(
        call_pc=0x200,
        target_address=VulnCallParam(
            is_adversary_controllable=target_ctrl,
            is_risky_fixed=not target_ctrl,
        ),
        function_selector=VulnCallParam(
            is_adversary_controllable=False,
            is_risky_fixed=True,
        ),
        recipient_arg=VulnCallParam(
            is_adversary_controllable=recipient_ctrl,
            is_risky_fixed=False,
            tainted_bytes=list(range(4, 36)),
        ),
        amount_arg=VulnCallParam(
            is_adversary_controllable=True,
            is_risky_fixed=False,
            tainted_bytes=list(range(36, 68)),
        ),
        requires_tx_origin_control=requires_phishing,
        path_constraints=[],
        confidence=0.9,
    )


def _make_ctx(
    vuln: PotentialVulnerability = None,
    with_exploit: bool = False,
    with_validated: bool = False,
) -> AnalysisContext:
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=b"\x60\x00\x00",
        contract_address="0xDeadBeef00000000000000000000000000000000",
        chain_id=1,
        block_number=20_000_000,
        config=config,
    )
    ctx.analysis_start = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    ctx.analysis_end = datetime.datetime(2025, 1, 1, 0, 0, 45, tzinfo=datetime.timezone.utc)
    ctx.coverage_before = 12.5
    ctx.coverage_after = 98.7
    ctx.is_obfuscated = True
    ctx.seed_inputs = []
    ctx.execution_traces = []
    ctx.potential_vulnerabilities = [vuln] if vuln else []

    if with_exploit and vuln:
        exp = Exploit(
            vuln_call_pc=vuln.call_pc,
            from_address="0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000",
            to_address="0xDeadBeef00000000000000000000000000000000",
            calldata=b"\xa9\x05\x9c\xbb" + b"\x00" * 64,
            target_token="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            target_token_symbol="WETH",
            expected_transfer_amount=10 ** 18,
            estimated_loss_usd=3000.0,
        )
        ctx.exploits = [exp]

        if with_validated:
            val = ValidatedExploit(
                exploit=exp,
                success=True,
                tx_receipt={"gas_used": 45000, "success": True, "logs_count": 1, "return_data": ""},
                transfer_events=[{"address": "0xweth", "topics": [], "data": b""}],
                estimated_loss_usd=3000.0,
            )
            ctx.validated_exploits = [val]
    return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_json_report_schema_valid():
    """JSON report must contain all required top-level keys."""
    vuln = _make_vuln()
    ctx = _make_ctx(vuln=vuln, with_exploit=True, with_validated=True)

    config = AnalysisConfig()
    engine = ReportingEngine(config)
    summary = engine._build_summary(ctx)

    formatter = JSONReportFormatter()
    report = formatter.format(ctx, summary)

    assert "metadata" in report
    assert "contract" in report
    assert "obfuscation" in report
    assert "execution" in report
    assert "vulnerabilities" in report
    assert "exploits" in report
    assert "summary" in report

    assert report["metadata"]["tool"] == "Little Bodi"
    assert len(report["vulnerabilities"]) == 1
    assert report["vulnerabilities"][0]["call_pc"] == hex(0x200)


def test_markdown_report_generated():
    """Markdown report must be non-empty and contain all core sections."""
    vuln = _make_vuln()
    ctx = _make_ctx(vuln=vuln, with_exploit=True, with_validated=True)

    config = AnalysisConfig()
    engine = ReportingEngine(config)
    summary = engine._build_summary(ctx)

    formatter = MarkdownReportFormatter()
    md = formatter.format(ctx, summary)

    assert "# Little Bodi Analysis Report" in md
    assert "## Obfuscation Analysis" in md
    assert "## Vulnerability Summary" in md
    assert "## Exploit Summary" in md
    assert "## Estimated Financial Impact" in md
    assert "## Mitigations" in md
    assert "0xDeadBeef" in md


def test_zero_vulnerability_report():
    """A clean contract must produce a report with risk_level 'none'."""
    ctx = _make_ctx()
    ctx.potential_vulnerabilities = []
    ctx.exploits = []
    ctx.validated_exploits = []

    config = AnalysisConfig()
    engine = ReportingEngine(config)
    summary = engine._build_summary(ctx)

    assert summary.risk_level == "none"
    assert summary.vulnerability_count == 0
    assert summary.confirmed_exploit_count == 0

    formatter = JSONReportFormatter()
    report = formatter.format(ctx, summary)
    assert report["summary"]["total_vulnerabilities"] == 0
    assert report["summary"]["risk_level"] == "none"


def test_mitigation_generated_for_each_vuln_type():
    """Each vulnerability type must trigger relevant mitigation messages."""
    gen = MitigationGenerator()

    # Phishing vulnerability
    phish_vuln = _make_vuln(requires_phishing=True)
    mits = gen.generate(phish_vuln)
    assert any("tx.origin" in m for m in mits), "Must mention tx.origin for phishing vulns"

    # Fully controllable target
    ctrl_target_vuln = _make_vuln(target_ctrl=True)
    mits = gen.generate(ctrl_target_vuln)
    assert any("whitelist" in m.lower() or "token address" in m.lower() for m in mits)

    # Controllable recipient
    ctrl_recip_vuln = _make_vuln(recipient_ctrl=True)
    mits = gen.generate(ctrl_recip_vuln)
    assert any("recipient" in m.lower() or "access control" in m.lower() for m in mits)

    # Gas note always present
    for vuln in [phish_vuln, ctrl_target_vuln, ctrl_recip_vuln]:
        mits = gen.generate(vuln)
        assert any("gas" in m.lower() for m in mits), "Gas cost note must always appear"


def test_risk_level_critical_above_1m():
    """Risk level must be 'critical' when confirmed exploits and loss > $1M."""
    summary = AnalysisSummary(
        contract_address="0xDeadBeef",
        is_vulnerable=True,
        vulnerability_count=1,
        confirmed_exploit_count=1,
        total_estimated_loss_usd=5_000_000.0,
        obfuscation_detected=True,
        coverage_improvement=86.2,
        analysis_duration_seconds=45.0,
        mode_used="concolic",
    )
    assert summary.risk_level == "critical"


def test_report_files_written_to_disk():
    """ReportingEngine must write report files to the output_dir."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = AnalysisConfig(output_dir=tmpdir, report_formats=["json", "markdown"])
        engine = ReportingEngine(config)

        vuln = _make_vuln()
        ctx = _make_ctx(vuln=vuln, with_exploit=True, with_validated=True)

        ctx = engine.execute(ctx)

        # Check that files were created
        files = os.listdir(tmpdir)
        assert any(f.endswith(".json") for f in files), "JSON report not written"
        assert any(f.endswith(".md") for f in files), "Markdown report not written"

        # Validate the JSON is parseable
        json_file = [f for f in files if f.endswith(".json")][0]
        with open(os.path.join(tmpdir, json_file)) as f:
            data = json.load(f)
        assert "metadata" in data
