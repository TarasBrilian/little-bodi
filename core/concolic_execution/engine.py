# core/concolic_execution/engine.py
from __future__ import annotations
import logging
import time
import z3
from typing import List, Optional, Dict, Any, Union

from core.pipeline import BaseEngine, AnalysisContext, AnalysisConfig, EngineInputError
from core.concolic_execution.models import SeedInput, ConcolicConfig, ConcolicOutput
from core.concolic_execution.seed_extractor import SeedExtractor
from core.concolic_execution.state import ConcolicState
from core.symbolic_execution.engine import SymbolicExecutionEngine
from core.symbolic_execution.state import SymbolicState
from core.symbolic_execution.interpreter import SymbolicEVMInterpreter, ExecutionResult
from core.constants import (
    OP_JUMP, OP_JUMPI, OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT,
    OP_CALLDATALOAD, OP_CALLER, OP_CALLVALUE
)

logger = logging.getLogger(__name__)

class ConcolicInterpreter(SymbolicEVMInterpreter):
    """
    Specialized interpreter for concolic execution.
    Follows a concrete trace from a seed while tracking symbolic expressions.
    """
    def __init__(self, bytecode: bytes, cfg: Any, config: Any, seed: SeedInput):
        super().__init__(bytecode, cfg, config)
        self.seed = seed
        # Dual track stack: stores (concrete_val, symbolic_ref)
        # However, to keep it compatible with SymbolicState, we'll store tuples.
        # This might require some adjustments in _handle_opcode if it expects just one value.
        # Actually, let's just use the symbolic stack and have a concrete model.

    def execute_seed(self, state: SymbolicState) -> List[SymbolicState]:
        """Executes a single path dictated by the seed."""
        # pc = 0
        # while ...
        #   instr = ...
        #   if JUMPI:
        #     use concrete calldata to decide
        #     add symbolic constraint
        
        # Initialize state with seed context
        # We merge caller, origin, value into the symbolic state
        state.caller = int(self.seed.caller, 16)
        state.origin = int(self.seed.origin, 16)
        state.callvalue = self.seed.value
        
        # PC, stack, memory are already in 'state'
        
        while state.pc < len(self.bytecode):
            instr = self.disassembly.get(state.pc)
            if not instr:
                return [state] # End of recognized code
            
            next_pc = state.pc + instr.size
            op = instr.opcode
            
            if op in (OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT):
                state.pc = next_pc
                return [state]

            if op == OP_JUMP:
                if not state.stack: break
                dest = state.stack.pop()
                # dest can be symbolic, but in concolic we usually know the concrete dest
                # If we don't, we prune or try to solve.
                if isinstance(dest, int):
                    state.pc = dest
                    continue
                else:
                    # Try to evaluate concrete value from symbolic expression?
                    # For simplicity in 'follow-the-seed', we assume we know where it went.
                    break 
            
            if op == OP_JUMPI:
                if len(state.stack) < 2: break
                dest = state.stack.pop()
                condition = state.stack.pop()
                
                # Concrete decision
                cond_val = self._evaluate_concrete(condition)
                
                if isinstance(dest, int):
                    z3_cond = self._to_z3(condition)
                    if cond_val != 0:
                        state.path_constraints.append(z3_cond != 0)
                        state.pc = dest
                        continue
                    else:
                        state.path_constraints.append(z3_cond == 0)
                        # fallthrough handled by end of loop
                else:
                    break

            # Handle CALLDATALOAD specially for seeds
            if op == OP_CALLDATALOAD:
                if not state.stack: break
                offset = state.stack.pop()
                concrete_offset = self._evaluate_concrete(offset)
                
                # Fetch concrete value from seed calldata
                chunk = self.seed.calldata[concrete_offset : concrete_offset + 32]
                chunk = chunk.ljust(32, b'\x00')
                concrete_val = int.from_bytes(chunk, 'big')
                
                # Create symbolic variable but "connected" to this concrete value
                sym_val = z3.BitVec(f"calldata_{state.pc}", 256)
                # We don't add constraint yet, but we mark it tainted
                state.taint_map.mark_tainted(sym_val, "calldata", concrete_offset)
                state.stack.append(sym_val)
                
                # Important: we need to keep track of the concrete value for this sym_val
                # For now, let's just push a tuple or use a mapping.
                # Actually, a simpler way: just push the concrete_val and keep a separate taint track.
                # BUT we need symbolic for path constraints.
                
                state.pc = next_pc
                continue

            # Default opcode handling
            success = self._handle_opcode(state, instr)
            if not success: break
            
            state.pc = next_pc
            
        return [state]

    def _evaluate_concrete(self, val: Any) -> int:
        """Heuristic to get a concrete value for execution decisions."""
        if isinstance(val, int):
            return val
        # If symbolic, we'd ideally use a solver with the seed's model.
        # For now, we'll try to keep concrete values on stack as much as possible.
        return 0 

class ConcolicEngine(BaseEngine):
    """
    Concolic Execution Engine.
    Uses historical seeds to guide symbolic execution.
    """
    def validate_input(self, ctx: AnalysisContext) -> None:
        if ctx.cfg is None:
            raise EngineInputError("Missing CFG in AnalysisContext")

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        extractor = SeedExtractor(self.config.rpc_url)
        # In a real scenario, we would use extractor to get seeds
        # For now, we use what's in context or fallback
        seeds = ctx.seed_inputs
        
        # If no seeds and fallback enabled, run symbolic
        if not seeds and self.config.fallback_to_symbolic:
            logger.info("No seeds available, falling back to symbolic execution.")
            from core.symbolic_execution.engine import SymbolicExecutionEngine
            sym_engine = SymbolicExecutionEngine(self.config)
            return sym_engine.execute(ctx)

        all_traces: List[SymbolicState] = []
        start_time = time.time()
        
        for seed_data in seeds:
            if time.time() - start_time > self.config.timeout_per_contract:
                break
            
            # Convert dict/BaseModel seed to SeedInput if needed
            if isinstance(seed_data, dict):
                seed = SeedInput(**seed_data)
            else:
                seed = seed_data
            
            # Initialize fresh ConcolicState for each seed
            initial_state = ConcolicState(pc=0)
            
            from core.concolic_execution.interpreter import ConcolicInterpreter
            interpreter = ConcolicInterpreter(ctx.bytecode, ctx.cfg, self.config, seed)
            traces = interpreter.execute_seed(initial_state)
            all_traces.extend(traces)

        ctx.execution_traces.extend(all_traces)
        
        # Extract potential vulnerabilities from traces
        for state in all_traces:
            for call in state.calls_encountered:
                if call not in ctx.potential_vulnerabilities:
                    ctx.potential_vulnerabilities.append(call)
                    
        return ctx
