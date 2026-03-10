# core/concolic_execution/interpreter.py
from __future__ import annotations
import z3
import logging
from typing import List, Dict, Optional, Any, Union, Tuple

from core.constants import (
    OP_JUMP, OP_JUMPI, OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT,
    OP_CALLDATALOAD, OP_CALLER, OP_CALLVALUE, OP_MLOAD, OP_MSTORE, OP_MSTORE8,
    OP_SLOAD, OP_SSTORE,
    OP_CALL, OP_CALLCODE, OP_STATICCALL, OP_DELEGATECALL,
    OP_PUSH1, OP_PUSH32, OP_DUP1, OP_DUP16, OP_SWAP1, OP_SWAP16, OP_POP, OP_PC, OP_GAS, OP_MSIZE,
    OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO, OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_SAR
)
from core.symbolic_execution.interpreter import SymbolicEVMInterpreter, ExecutionResult
from core.concolic_execution.state import ConcolicState
from core.concolic_execution.models import SeedInput

logger = logging.getLogger(__name__)

class ConcolicInterpreter(SymbolicEVMInterpreter):
    """
    Dual-track EVM Interpreter:
    - Concrete Track: uses seed values to make execution decisions (which branch to take).
    - Symbolic Track: tracks z3 expressions for constraints and taint analysis.
    """
    def __init__(self, bytecode: bytes, cfg: Any, config: Any, seed: SeedInput):
        super().__init__(bytecode, cfg, config)
        self.seed = seed

    def execute_seed(self, initial_state: ConcolicState) -> List[ConcolicState]:
        """Runs the concolic execution for a single seed input."""
        state = initial_state
        
        # Initialize context from seed
        state.caller = int(self.seed.caller, 16)
        state.origin = int(self.seed.origin, 16)
        state.callvalue = self.seed.value
        
        logger.info(f"Executing seed trace: caller={self.seed.caller}, value={self.seed.value}")
        
        while state.pc < len(self.bytecode):
            instr = self.disassembly.get(state.pc)
            if not instr:
                break
                
            next_pc = state.pc + instr.size
            op = instr.opcode
            
            # Terminal opcodes
            if op in (OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT):
                state.pc = next_pc
                return [state]
            
            # Control flow
            if op == OP_JUMP:
                if not state.concrete_stack: break
                concrete_dest, _ = state.pop_both()
                state.pc = concrete_dest
                continue
            
            if op == OP_JUMPI:
                if len(state.concrete_stack) < 2: break
                dest_concrete, dest_sym = state.pop_both()
                cond_concrete, cond_sym = state.pop_both()
                
                # In concolic execution, we follow the concrete condition from the seed
                z3_cond = self._to_z3(cond_sym)
                if cond_concrete != 0:
                    state.path_constraints.append(z3_cond != 0)
                    state.pc = dest_concrete
                else:
                    state.path_constraints.append(z3_cond == 0)
                    state.pc = next_pc
                continue

            # Special cases for concolic inputs
            if op == OP_CALLDATALOAD:
                if not state.concrete_stack: break
                offset_concrete, offset_sym = state.pop_both()
                
                # Concrete fetch
                chunk = self.seed.calldata[offset_concrete : offset_concrete + 32]
                chunk = chunk.ljust(32, b'\x00')
                concrete_val = int.from_bytes(chunk, 'big')
                
                # Symbolic variable
                sym_val = z3.BitVec(f"calldata_{state.pc}", 256)
                # Link to concrete value for potential later mutation/analysis?
                # For now, just track taint.
                state.taint_map.mark_tainted(sym_val, "calldata", offset_concrete)
                
                state.push_both(concrete_val, sym_val)
                state.pc = next_pc
                continue

            # Standard opcode handling (we wrap the original logic to maintain both tracks)
            success = self._handle_opcode(state, instr)
            if not success:
                break
                
            state.pc = next_pc
            
        return [state]

    def _handle_opcode(self, state: ConcolicState, instr: Any) -> bool:
        """
        Extends SymbolicEVMInterpreter._handle_opcode to maintain dual-track state.
        Calculates concrete results alongside symbolic expressions.
        """
        op = instr.opcode
        
        # We'll use a helper to wrap arithmetic/comparison results
        if op in (OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_SAR):
            if len(state.concrete_stack) < 2: return False
            a_c = state.concrete_stack[-1]
            b_c = state.concrete_stack[-2]
            
            # Calculate concrete result
            res_c = 0
            if op == OP_ADD: res_c = (a_c + b_c) & (2**256 - 1)
            elif op == OP_MUL: res_c = (a_c * b_c) & (2**256 - 1)
            elif op == OP_SUB: res_c = (a_c - b_c) & (2**256 - 1)
            elif op == OP_DIV: res_c = (a_c // b_c) if b_c != 0 else 0
            elif op == OP_AND: res_c = a_c & b_c
            elif op == OP_OR: res_c = a_c | b_c
            elif op == OP_XOR: res_c = a_c ^ b_c
            elif op == OP_SHL: res_c = (b_c << a_c) & (2**256 - 1)
            elif op == OP_SHR: res_c = b_c >> a_c
            elif op == OP_SAR:
                if b_c & (1 << 255):
                    res_c = (b_c >> a_c) | (2**256 - (1 << (256 - a_c))) if a_c < 256 else (2**256 - 1)
                else:
                    res_c = b_c >> a_c
            
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                state.concrete_stack.pop()
                state.concrete_stack.append(res_c)
            return success

        if op in (OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO):
            if op == OP_ISZERO:
                if not state.concrete_stack: return False
                a_c = state.concrete_stack[-1]
                res_c = 1 if a_c == 0 else 0
                success = super()._handle_opcode(state, instr)
                if success:
                    state.concrete_stack.pop()
                    state.concrete_stack.append(res_c)
                return success
                
            if len(state.concrete_stack) < 2: return False
            a_c = state.concrete_stack[-1]
            b_c = state.concrete_stack[-2]
            
            res_c = 0
            if op == OP_LT: res_c = 1 if a_c < b_c else 0
            elif op == OP_GT: res_c = 1 if a_c > b_c else 0
            elif op == OP_EQ: res_c = 1 if a_c == b_c else 0
            # ... support other comparisons if needed
            
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                state.concrete_stack.pop()
                state.concrete_stack.append(res_c)
            return success

        if op == OP_MLOAD:
            if not state.concrete_stack: return False
            off_c = state.concrete_stack[-1]
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                val_c = state.concrete_memory.get(off_c, 0)
                state.concrete_stack.append(val_c)
            return success

        if op == OP_MSTORE:
            if len(state.concrete_stack) < 2: return False
            off_c = state.concrete_stack[-1]
            val_c = state.concrete_stack[-2]
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                state.concrete_stack.pop()
                state.concrete_memory[off_c] = val_c
            return success

        if op == OP_MSTORE8:
            if len(state.concrete_stack) < 2: return False
            off_c = state.concrete_stack[-1]
            val_c = state.concrete_stack[-2]
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                state.concrete_stack.pop()
                state.concrete_memory[off_c] = val_c & 0xFF
            return success

        if op == OP_SLOAD:
            if not state.concrete_stack: return False
            slot_c = state.concrete_stack[-1]
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                val_c = state.concrete_storage.get(slot_c, 0)
                state.concrete_stack.append(val_c)
            return success

        if op == OP_SSTORE:
            if len(state.concrete_stack) < 2: return False
            slot_c = state.concrete_stack[-1]
            val_c = state.concrete_stack[-2]
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.pop()
                state.concrete_stack.pop()
                state.concrete_storage[slot_c] = val_c
            return success

        if op in (OP_CALL, OP_STATICCALL, OP_DELEGATECALL, OP_CALLCODE):
            required = 7 if op in (OP_CALL, OP_CALLCODE) else 6
            if len(state.concrete_stack) < required: return False
            
            # Pop from concrete stack
            for _ in range(required):
                state.concrete_stack.pop()
                
            success = super()._handle_opcode(state, instr)
            if success:
                state.concrete_stack.append(1) # Concrete success
            return success

        # Stack Operations
        if 0x60 <= op <= 0x7F: # PUSHx
            val = int.from_bytes(instr.operand if instr.operand else b'', 'big')
            state.push_both(val, val)
            return True
            
        if 0x80 <= op <= 0x8F: # DUPx
            idx = op - 0x80 + 1
            if len(state.concrete_stack) < idx: return False
            state.push_both(state.concrete_stack[-idx], state.stack[-idx])
            return True
            
        if 0x90 <= op <= 0x9F: # SWAPx
            idx = op - 0x90 + 1
            if len(state.concrete_stack) < idx + 1: return False
            state.concrete_stack[-1], state.concrete_stack[-idx-1] = state.concrete_stack[-idx-1], state.concrete_stack[-1]
            state.stack[-1], state.stack[-idx-1] = state.stack[-idx-1], state.stack[-1]
            return True
            
        if op == OP_POP:
            if not state.concrete_stack: return False
            state.pop_both()
            return True

        if op == OP_CALLER:
            state.push_both(state.caller, state.caller)
            return True
            
        if op == OP_CALLVALUE:
            state.push_both(state.callvalue, state.callvalue)
            return True

        # Default fallback
        return super()._handle_opcode(state, instr)
