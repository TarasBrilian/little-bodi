# core/symbolic_execution/engine.py
from __future__ import annotations
import logging
from typing import List, Optional

from core.pipeline import BaseEngine, AnalysisContext, AnalysisConfig, EngineInputError
from core.symbolic_execution.state import SymbolicState
from core.symbolic_execution.interpreter import SymbolicEVMInterpreter

logger = logging.getLogger(__name__)

class SymbolicExecutionEngine(BaseEngine):
    """
    Orchestrates the symbolic execution of EVM bytecode to find reachable vulnerabilities.
    """

    def validate_input(self, ctx: AnalysisContext) -> None:
        """Ensures that the CFG and bytecode are available."""
        if ctx.cfg is None:
            raise EngineInputError("Missing CFG in AnalysisContext")
        if not ctx.bytecode:
            raise EngineInputError("Missing bytecode in AnalysisContext")

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        Executes the symbolic engine.
        """
        # Use deobfuscated CFG if available, otherwise fallback to original CFG
        cfg = ctx.deobfuscated_cfg or ctx.cfg
        bytecode = ctx.instrumented_bytecode or ctx.bytecode
        
        # Initialize Interpreter
        interpreter = SymbolicEVMInterpreter(bytecode, cfg, self.config)
        
        # Create Initial State
        initial_state = SymbolicState(pc=0)
        
        # Run Symbolic Execution
        traces = interpreter.execute(initial_state)
        
        # Update AnalysisContext
        ctx.execution_traces = traces
        
        # Extract potential vulnerabilities (encounters with CALL instructions)
        # Note: In a more modular design, this might be handled by VulnerabilityEngine,
        # but we record encounters here as per SYMBOLIC_EXECUTION_ENGINE.md
        all_calls = []
        for state in traces:
            all_calls.extend(state.calls_encountered)
            
        # Deduplicate calls by PC
        unique_calls = {call.pc: call for call in all_calls}.values()
        ctx.potential_vulnerabilities = list(unique_calls)
        
        logger.info(
            f"Symbolic execution complete: {len(traces)} paths explored, "
            f"{len(ctx.potential_vulnerabilities)} unique calls found"
        )
        
        return ctx
