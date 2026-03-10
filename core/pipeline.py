# core/pipeline.py
# Pipeline Orchestrator — calls all engines sequentially
# with shared AnalysisContext. This is the main entry point for analysis.

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.constants import ADVERSARY_ADDRESS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class AnalysisConfig:
    # RPC
    rpc_url: Optional[str] = None

    # Deobfuscation
    branch_table_offset: int = 0xE000
    intermediate_offset: int = 0xF000
    branch_table_max_visits: int = 2

    # Execution
    use_concolic: bool = True
    max_seeds: int = 50
    timeout_per_contract: int = 30
    max_symbolic_paths: int = 300
    max_path_depth: int = 75
    fallback_to_symbolic: bool = True
    stop_on_first_vuln: bool = True

    # Vulnerability / Exploit
    adversary_address: str = ADVERSARY_ADDRESS
    max_tokens_per_contract: int = 7
    gas_limit: int = 1_000_000

    # Output
    output_dir: str = "data/results"
    report_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])


# ---------------------------------------------------------------------------
# AnalysisContext — shared state passed between engines
# ---------------------------------------------------------------------------

@dataclass
class AnalysisContext:
    # --- Input ---
    bytecode: bytes
    contract_address: Optional[str]
    chain_id: int
    block_number: Optional[int]
    config: AnalysisConfig

    # --- Stage A: Bytecode Analysis ---
    disassembly: Optional[object] = None           # DisassemblyResult
    cfg: Optional[object] = None                   # ControlFlowGraph
    indirect_jumps: list = field(default_factory=list)
    jumpdests: set = field(default_factory=set)
    deobfuscated_cfg: Optional[object] = None
    instrumented_bytecode: Optional[bytes] = None
    coverage_before: float = 0.0
    coverage_after: float = 0.0
    is_obfuscated: bool = False

    # --- Stage B: Vulnerability Detection ---
    seed_inputs: list = field(default_factory=list)
    execution_traces: list = field(default_factory=list)
    fell_back_to_symbolic: bool = False
    potential_vulnerabilities: list = field(default_factory=list)

    # --- Stage C: Exploit Generation & Validation ---
    exploits: list = field(default_factory=list)
    validated_exploits: list = field(default_factory=list)

    # --- Metadata ---
    report_files: list[str] = field(default_factory=list)
    analysis_summary: Optional[object] = None
    analysis_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_end: Optional[datetime] = None
    errors: list[dict] = field(default_factory=list)

    def record_error(self, engine: str, error: Exception) -> None:
        self.errors.append({
            "engine": engine,
            "error_type": type(error).__name__,
            "message": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        logger.error(f"[{engine}] {type(error).__name__}: {error}")

    @property
    def duration_seconds(self) -> float:
        end = self.analysis_end or datetime.now(timezone.utc)
        return (end - self.analysis_start).total_seconds()


# ---------------------------------------------------------------------------
# Base Engine Interface
# ---------------------------------------------------------------------------

class EngineError(Exception):
    pass

class EngineInputError(EngineError):
    pass


class BaseEngine:
    """
    All engines inherit from this.
    Implement run() and validate_input().
    Do not override execute() — it's a template method.
    """

    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        raise NotImplementedError

    def validate_input(self, ctx: AnalysisContext) -> None:
        """Raise EngineInputError if context is not valid for this engine."""
        raise NotImplementedError

    def execute(self, ctx: AnalysisContext) -> AnalysisContext:
        """Template method. Do not override."""
        self.validate_input(ctx)
        start = time.perf_counter()
        try:
            result = self.run(ctx)
        except EngineError:
            raise
        except Exception as e:
            ctx.record_error(self.__class__.__name__, e)
            return ctx
        elapsed = time.perf_counter() - start
        self.logger.info(f"Completed in {elapsed:.2f}s")
        return result


# ---------------------------------------------------------------------------
# Pipeline Orchestrator
# ---------------------------------------------------------------------------

class AnalysisPipeline:
    """
    Orchestrates all engines in the correct order.
    Each engine receives and returns an AnalysisContext.

    Order:
        Stage A: BytecodeAnalysisEngine → DeobfuscationEngine
        Stage B: ConcolicEngine (or SymbolicExecutionEngine) → VulnerabilityEngine
        Stage C: ExploitGenerationEngine → ValidationEngine → ReportingEngine
    """

    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self._engines: list[BaseEngine] = []
        self._build_pipeline()

    def _build_pipeline(self) -> None:
        """
        Import engines here (lazy import) to avoid circular dependency.
        Each engine file is in core/<name>.py
        """
        # During development, these engines are imported one by one.
        # Example import (uncomment as they are implemented):
        #
        from core.bytecode_analysis.engine import BytecodeAnalysisEngine
        from core.deobfuscation.engine import DeobfuscationEngine
        from core.concolic_execution.engine import ConcolicEngine
        from core.symbolic_execution.engine import SymbolicExecutionEngine
        from core.vulnerability.engine import VulnerabilityEngine
        from core.exploit_generation.engine import ExploitGenerationEngine
        from core.validation.engine import ValidationEngine
        from core.reporting.engine import ReportingEngine
        
        self._engines = [
            BytecodeAnalysisEngine(self.config),
            DeobfuscationEngine(self.config),
            ConcolicEngine(self.config) if self.config.use_concolic
                else SymbolicExecutionEngine(self.config),
            VulnerabilityEngine(self.config),
            ExploitGenerationEngine(self.config),
            ValidationEngine(self.config),
            ReportingEngine(self.config),
        ]

    def run(
        self,
        bytecode: bytes,
        contract_address: Optional[str] = None,
        chain_id: int = 1,
        block_number: Optional[int] = None,
    ) -> AnalysisContext:
        """
        Main entry point for the pipeline.
        Returns AnalysisContext filled with all analysis results.
        """
        ctx = AnalysisContext(
            bytecode=bytecode,
            contract_address=contract_address,
            chain_id=chain_id,
            block_number=block_number,
            config=self.config,
        )

        logger.info(
            f"Starting analysis | contract={contract_address} "
            f"| bytecode_size={len(bytecode)} bytes"
        )

        for engine in self._engines:
            engine_name = engine.__class__.__name__
            logger.info(f"Running {engine_name}...")

            try:
                ctx = engine.execute(ctx)
            except EngineInputError as e:
                logger.warning(f"{engine_name} skipped: {e}")
                continue
            except Exception as e:
                logger.error(f"{engine_name} failed: {e}")
                ctx.record_error(engine_name, e)
                # Some engines can be skipped (exploit gen, validation)
                # but Stage A failure must stop the pipeline
                if engine_name in ("BytecodeAnalysisEngine", "DeobfuscationEngine"):
                    logger.error("Critical engine failed. Stopping pipeline.")
                    break

        ctx.analysis_end = datetime.now(timezone.utc)
        logger.info(
            f"Analysis complete | duration={ctx.duration_seconds:.2f}s "
            f"| vulnerabilities={len(ctx.potential_vulnerabilities)} "
            f"| validated_exploits={len(ctx.validated_exploits)}"
        )

        return ctx


# ---------------------------------------------------------------------------
# Convenience function for single-contract analysis
# ---------------------------------------------------------------------------

def analyze_contract(
    bytecode_hex: str,
    contract_address: Optional[str] = None,
    rpc_url: Optional[str] = None,
    block_number: Optional[int] = None,
    chain_id: int = 1,
    **config_kwargs,
) -> AnalysisContext:
    """
    High-level function for single-contract analysis.

    Usage:
        ctx = analyze_contract(
            bytecode_hex="0x6080604052...",
            contract_address="0x...",
            rpc_url="https://...",
        )
        print(ctx.validated_exploits)
    """
    # Strip 0x prefix if present
    bytecode_hex = bytecode_hex.removeprefix("0x")
    bytecode = bytes.fromhex(bytecode_hex)

    config = AnalysisConfig(
        rpc_url=rpc_url,
        **config_kwargs
    )

    pipeline = AnalysisPipeline(config)
    return pipeline.run(
        bytecode=bytecode,
        contract_address=contract_address,
        chain_id=chain_id,
        block_number=block_number,
    )
