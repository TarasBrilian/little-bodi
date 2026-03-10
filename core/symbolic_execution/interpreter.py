# core/symbolic_execution/interpreter.py
from __future__ import annotations
import z3
import logging
import time
from typing import List, Dict, Optional, Tuple, Set, Union, Any
from dataclasses import dataclass

from core.constants import (
    OP_JUMP, OP_JUMPI, OP_JUMPDEST, OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT,
    OP_CALLDATALOAD, OP_CALLDATASIZE, OP_CALLDATACOPY,
    OP_CALLER, OP_CALLVALUE,
    OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_SDIV, OP_MOD, OP_SMOD, OP_ADDMOD, OP_MULMOD, OP_EXP, OP_SIGNEXTEND,
    OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO, OP_AND, OP_OR, OP_XOR, OP_NOT, OP_BYTE, OP_SHL, OP_SHR, OP_SAR,
    OP_POP, OP_MLOAD, OP_MSTORE, OP_MSTORE8, OP_SLOAD, OP_SSTORE, OP_PC, OP_MSIZE, OP_GAS,
    OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL,
    BRANCH_TABLE_OFFSET, EVM_WORD_BITS
)
from core.bytecode_analysis.engine import ControlFlowGraph, Instruction, BasicBlock
from core.symbolic_execution.state import SymbolicState, CallEncounter, CallTaintInfo

logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    """Outcome of executing a block or instruction."""
    type: str # "terminal", "fork", "continue", "prune"
    states: List[SymbolicState] = None
    reason: Optional[str] = None

    @classmethod
    def terminal(cls) -> ExecutionResult:
        return cls(type="terminal")

    @classmethod
    def continue_(cls, state: SymbolicState) -> ExecutionResult:
        return cls(type="continue", states=[state])

    @classmethod
    def fork(cls, taken: SymbolicState, fallthrough: SymbolicState) -> ExecutionResult:
        return cls(type="fork", states=[taken, fallthrough])

    @classmethod
    def prune(cls, reason: str) -> ExecutionResult:
        return cls(type="prune", reason=reason)

class SymbolicEVMInterpreter:
    """
    Symbolic EVM Interpreter that executes paths and handles state forking.
    """
    def __init__(self, bytecode: bytes, cfg: ControlFlowGraph, config: Any):
        self.bytecode = bytecode
        self.cfg = cfg
        self.config = config
        self.disassembly: Dict[int, Instruction] = self._flatten_cfg(cfg)

    def _flatten_cfg(self, cfg: ControlFlowGraph) -> Dict[int, Instruction]:
        """
        Creates a PC -> Instruction mapping by disassembling the bytecode.
        Ensures consistency with the actually executed bytecode.
        """
        import pyevmasm
        instrs = {}
        # Decode all instructions in the bytecode
        for jinstr in pyevmasm.disassemble_all(self.bytecode):
            operand = jinstr.operand
            if isinstance(operand, int):
                # Convert int operand to bytes, using size to determine width
                # size = 1 (opcode) + operand_size
                operand_size = jinstr.size - 1
                if operand_size > 0:
                    operand = operand.to_bytes(operand_size, 'big')
                else:
                    operand = None
                    
            instrs[jinstr.pc] = Instruction(
                pc=jinstr.pc,
                opcode=jinstr.opcode,
                mnemonic=jinstr.mnemonic,
                operand=operand,
                size=jinstr.size
            )
        return instrs

    def execute(self, initial_state: SymbolicState) -> List[SymbolicState]:
        """Explores paths using DFS."""
        traces: List[SymbolicState] = []
        worklist: List[SymbolicState] = [initial_state]
        paths_explored = 0
        start_time = time.time()
        
        logger.info(f"Starting symbolic execution at PC {initial_state.pc}")
        
        while worklist and paths_explored < self.config.max_symbolic_paths:
            if time.time() - start_time > self.config.timeout_per_contract:
                logger.warning("Symbolic execution timeout reached")
                break
            
            state = worklist.pop()
            
            # DFS exploration
            result = self._execute_path(state)
            if result.type == "terminal":
                logger.debug(f"Path reached terminal at PC {state.pc}")
                traces.append(state)
                paths_explored += 1
            elif result.type == "fork":
                # Add feasible paths to worklist
                for s in reversed(result.states):
                    if s.is_feasible():
                        worklist.append(s)
                    else:
                        logger.debug(f"Infeasible path pruned at PC {s.pc}")
            elif result.type == "continue":
                worklist.append(result.states[0])
            elif result.type == "prune":
                logger.debug(f"Path pruned: {result.reason} (PC: {state.pc})")

        return traces

    def _execute_path(self, state: SymbolicState) -> ExecutionResult:
        """Executes instructions until a fork or terminal opcode is hit."""
        while state.pc < len(self.bytecode):
            instr = self.disassembly.get(state.pc)
            if not instr:
                return ExecutionResult.prune(f"No instruction at PC {state.pc}")
            
            # Step PC
            next_pc = state.pc + instr.size
            
            # opcode handling
            op = instr.opcode
            
            if op in (OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT):
                state.pc = next_pc # Record final PC
                return ExecutionResult.terminal()
            
            if op == OP_JUMP:
                if not state.stack: return ExecutionResult.prune("Stack underflow at JUMP")
                dest = state.stack.pop()
                if isinstance(dest, int):
                    state.pc = dest
                    continue
                else:
                    return ExecutionResult.prune("Symbolic JUMP destination")
            
            if op == OP_JUMPI:
                if len(state.stack) < 2: return ExecutionResult.prune("Stack underflow at JUMPI")
                dest = state.stack.pop()
                condition = state.stack.pop()
                
                if isinstance(dest, int):
                    # Fork
                    z3_condition = self._to_z3(condition)
                    
                    taken = state.fork(z3_condition != 0)
                    taken.pc = dest
                    
                    fallthrough = state.fork(z3_condition == 0)
                    fallthrough.pc = next_pc
                    
                    # Branch table visit count (pruning rule)
                    if dest == BRANCH_TABLE_OFFSET:
                        taken.branch_table_visits += 1
                        if taken.branch_table_visits > self.config.branch_table_max_visits:
                            return ExecutionResult.continue_(fallthrough)
                    
                    return ExecutionResult.fork(taken, fallthrough)
                else:
                    return ExecutionResult.prune("Symbolic JUMPI destination")

            # Handle other opcodes
            success = self._handle_opcode(state, instr)
            if not success:
                return ExecutionResult.prune(f"Failed opcode {instr.mnemonic}")
            
            state.pc = next_pc
            
            # Depth limit check
            if len(state.path_constraints) > self.config.max_path_depth:
                return ExecutionResult.prune("Max path depth reached")

        return ExecutionResult.terminal()

    def _handle_opcode(self, state: SymbolicState, instr: Instruction) -> bool:
        """Dispatches to specific opcode handlers."""
        op = instr.opcode
        
        if op == OP_CALLER:
            state.stack.append(state.caller)
            return True
            
        if op == OP_CALLVALUE:
            state.stack.append(state.callvalue)
            return True

        # PUSHx
        if 0x60 <= op <= 0x7F:
            val = int.from_bytes(instr.operand if instr.operand else b'', 'big')
            state.stack.append(val)
            return True
            
        # DUPx
        if 0x80 <= op <= 0x8F:
            idx = op - 0x80 + 1
            if len(state.stack) < idx: return False
            state.stack.append(state.stack[-idx])
            return True
            
        # SWAPx
        if 0x90 <= op <= 0x9F:
            idx = op - 0x90 + 1
            if len(state.stack) < idx + 1: return False
            state.stack[-1], state.stack[-idx - 1] = state.stack[-idx - 1], state.stack[-1]
            return True

        # Simple Arithmetic & Bitwise
        if op in (OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_SAR):
            if len(state.stack) < 2: return False
            a = state.stack.pop()
            b = state.stack.pop()
            
            res_name = f"res_{instr.pc}_{len(state.path_constraints)}"
            res = z3.BitVec(res_name, 256)
            
            if op == OP_ADD: state.path_constraints.append(res == (self._to_z3(a) + self._to_z3(b)))
            elif op == OP_SUB: state.path_constraints.append(res == (self._to_z3(a) - self._to_z3(b)))
            elif op == OP_AND: state.path_constraints.append(res == (self._to_z3(a) & self._to_z3(b)))
            elif op == OP_OR: state.path_constraints.append(res == (self._to_z3(a) | self._to_z3(b)))
            elif op == OP_XOR: state.path_constraints.append(res == (self._to_z3(a) ^ self._to_z3(b)))
            elif op == OP_SHL: state.path_constraints.append(res == (self._to_z3(b) << self._to_z3(a)))
            elif op == OP_SHR: state.path_constraints.append(res == z3.LShR(self._to_z3(b), self._to_z3(a)))
            elif op == OP_SAR: state.path_constraints.append(res == (self._to_z3(b) >> self._to_z3(a)))
            
            # Taint propagation
            if state.taint_map.is_tainted(a) or state.taint_map.is_tainted(b):
                state.taint_map.mark_tainted(res, "derived")
                
            state.stack.append(res)
            return True

        # Comparisons
        if op in (OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO):
            if op == OP_ISZERO:
                if not state.stack: return False
                a = state.stack.pop()
                res = z3.BitVec(f"iszero_{instr.pc}_{len(state.path_constraints)}", 256)
                state.path_constraints.append(res == z3.If(self._to_z3(a) == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
                
                if state.taint_map.is_tainted(a):
                    state.taint_map.mark_tainted(res, "derived")
                    
                state.stack.append(res)
                return True
            
            if len(state.stack) < 2: return False
            a = state.stack.pop()
            b = state.stack.pop()
            res = z3.BitVec(f"cmp_{instr.pc}_{len(state.path_constraints)}", 256)
            
            cond = None
            if op == OP_LT: cond = z3.ULT(self._to_z3(a), self._to_z3(b))
            elif op == OP_GT: cond = z3.UGT(self._to_z3(a), self._to_z3(b))
            elif op == OP_SLT: cond = (self._to_z3(a) < self._to_z3(b))
            elif op == OP_SGT: cond = (self._to_z3(a) > self._to_z3(b))
            elif op == OP_EQ: cond = (self._to_z3(a) == self._to_z3(b))
            
            if cond is not None:
                state.path_constraints.append(res == z3.If(cond, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            
            if state.taint_map.is_tainted(a) or state.taint_map.is_tainted(b):
                state.taint_map.mark_tainted(res, "derived")
                
            state.stack.append(res)
            return True

        if op == OP_CALLDATALOAD:
            if not state.stack: return False
            offset = state.stack.pop()
            sym_val = z3.BitVec(f"calldata_{instr.pc}_{len(state.path_constraints)}", 256)
            state.taint_map.mark_tainted(sym_val, "calldata", offset if isinstance(offset, int) else None)
            state.stack.append(sym_val)
            return True

        if op in (OP_CALL, OP_STATICCALL, OP_DELEGATECALL, OP_CALLCODE):
            if op in (OP_CALL, OP_CALLCODE):
                if len(state.stack) < 7: return False
                gas = state.stack.pop()
                to = state.stack.pop()
                val = state.stack.pop()
                in_off = state.stack.pop()
                in_size = state.stack.pop()
                out_off = state.stack.pop()
                out_size = state.stack.pop()
            else: # STATICCALL, DELEGATECALL
                if len(state.stack) < 6: return False
                gas = state.stack.pop()
                to = state.stack.pop()
                val = 0 # No value for static/delegate
                in_off = state.stack.pop()
                in_size = state.stack.pop()
                out_off = state.stack.pop()
                out_size = state.stack.pop()
            
            encounter = CallEncounter(
                pc=instr.pc, gas=gas, target_address=to, value=val,
                args_offset=in_off, args_size=in_size
            )
            
            # Try to extract function selector and arguments from memory
            # Note: This assumes standard ABI calldata layout
            if isinstance(in_off, int):
                # We check the memory at in_off. 
                # Our memory is word-based (simplified), so in_off usually points to the start of a word.
                data_word0 = state.memory.get(in_off, None)
                if data_word0 is not None:
                    # Logic to extract selector (4 bytes) and arg1 (32 bytes)
                    # This is heuristic-based because we don't have a real byte-addressed memory.
                    encounter.function_selector = data_word0
                    
                    data_word1 = state.memory.get(in_off + 32, None) # Often arg1 starts at relative +4, but if they aligned...
                    # In many cases, arg1 is the SECOND word if selector is at the first word's top.
                    # This is very simplified.
                    encounter.arg1_recipient = data_word1
                    
                    data_word2 = state.memory.get(in_off + 64, None)
                    encounter.arg2_amount = data_word2

            encounter.taint.target_tainted = state.taint_map.is_tainted(to)
            encounter.taint.args_tainted = state.taint_map.is_tainted(in_off)
            
            # Save constraints for this specific call point
            encounter.path_constraints = [c for c in state.path_constraints]
            
            state.calls_encountered.append(encounter)
            state.stack.append(1) # Assume success
            return True

        if op == OP_POP:
            if state.stack: state.stack.pop()
            return True
            
        if op == OP_MLOAD:
            if not state.stack: return False
            offset = state.stack.pop()
            # Simplified memory: Dict[int, Union[z3.BitVecRef, int]]
            # Real EVM memory is byte-addressed.
            val = state.memory.get(offset if isinstance(offset, int) else str(offset), 0)
            
            if val == 0 and not isinstance(offset, int):
                # If symbolic offset and not found, create new symbolic memory value
                val = z3.BitVec(f"mem_{instr.pc}_{len(state.path_constraints)}", 256)
                # If offset is tainted, the memory access itself might be risky, 
                # but we'll mark the result derived if anything in memory was tainted.
                # Simplified: just return it.
                state.memory[str(offset)] = val
                
            state.stack.append(val)
            return True

        if op == OP_MSTORE:
            if len(state.stack) < 2: return False
            offset = state.stack.pop()
            value = state.stack.pop()
            state.memory[offset if isinstance(offset, int) else str(offset)] = value
            return True

        if op == OP_MSTORE8:
            if len(state.stack) < 2: return False
            offset = state.stack.pop()
            value = state.stack.pop()
            # Simplified: MSTORE8 treated like MSTORE for now
            state.memory[offset if isinstance(offset, int) else str(offset)] = value
            return True

        if op == OP_SLOAD:
            if not state.stack: return False
            slot = state.stack.pop()
            val = state.storage.get(slot if isinstance(slot, int) else str(slot), 0)
            
            if val == 0 and not isinstance(slot, int):
                val = z3.BitVec(f"storage_{instr.pc}_{len(state.path_constraints)}", 256)
                state.storage[str(slot)] = val
                
            state.stack.append(val)
            return True

        if op == OP_SSTORE:
            if len(state.stack) < 2: return False
            slot = state.stack.pop()
            value = state.stack.pop()
            state.storage[slot if isinstance(slot, int) else str(slot)] = value
            return True

        if op == OP_JUMPDEST:
            return True

        # Default: step over
        return True

    def _to_z3(self, val: Union[z3.BitVecRef, int]) -> z3.BitVecRef:
        if isinstance(val, int):
            return z3.BitVecVal(val, 256)
        if isinstance(val, z3.BoolRef):
            return z3.If(val, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))
        return val
