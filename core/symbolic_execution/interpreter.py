# core/symbolic_execution/interpreter.py
from __future__ import annotations
import z3
import logging
import time
import heapq
from typing import List, Dict, Optional, Tuple, Set, Union, Any
from dataclasses import dataclass
from collections import deque

from core.constants import (
    # Control flow
    OP_JUMP,
    OP_JUMPI,
    OP_JUMPDEST,
    OP_STOP,
    OP_RETURN,
    OP_REVERT,
    OP_INVALID,
    OP_SELFDESTRUCT,
    # Calldata
    OP_CALLDATALOAD,
    OP_CALLDATASIZE,
    OP_CALLDATACOPY,
    # Transaction context
    OP_CALLER,
    OP_CALLVALUE,
    OP_ORIGIN,
    # Arithmetic
    OP_ADD,
    OP_MUL,
    OP_SUB,
    OP_DIV,
    OP_SDIV,
    OP_MOD,
    OP_SMOD,
    OP_ADDMOD,
    OP_MULMOD,
    OP_EXP,
    OP_SIGNEXTEND,
    # Comparison / bitwise
    OP_LT,
    OP_GT,
    OP_SLT,
    OP_SGT,
    OP_EQ,
    OP_ISZERO,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_NOT,
    OP_BYTE,
    OP_SHL,
    OP_SHR,
    OP_SAR,
    # Hash
    OP_KECCAK256,
    # Environment — push-only (no inputs)
    OP_ADDRESS,
    OP_SELFBALANCE,
    OP_GASPRICE,
    OP_COINBASE,
    OP_TIMESTAMP,
    OP_NUMBER,
    OP_PREVRANDAO,
    OP_GASLIMIT,
    OP_CHAINID,
    OP_BASEFEE,
    OP_CODESIZE,
    OP_RETURNDATASIZE,
    # Environment — pop 1 push 1
    OP_BALANCE,
    OP_EXTCODESIZE,
    OP_EXTCODEHASH,
    OP_BLOCKHASH,
    # Memory / Storage
    OP_POP,
    OP_MLOAD,
    OP_MSTORE,
    OP_MSTORE8,
    OP_SLOAD,
    OP_SSTORE,
    OP_CODECOPY,
    OP_EXTCODECOPY,
    OP_RETURNDATACOPY,
    OP_PC,
    OP_MSIZE,
    OP_GAS,
    # Logging (pop-only, no push)
    OP_LOG0,
    OP_LOG4,
    # Contract creation
    OP_CREATE,
    OP_CREATE2,
    # Calls
    OP_CALL,
    OP_CALLCODE,
    OP_DELEGATECALL,
    OP_STATICCALL,
    # Project constants
    BRANCH_TABLE_OFFSET,
    EVM_WORD_BITS,
    OPCODE_TABLE,
)
from core.bytecode_analysis.engine import ControlFlowGraph, Instruction, BasicBlock
from core.symbolic_execution.state import SymbolicState, CallEncounter, CallTaintInfo

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Outcome of executing a block or instruction."""

    type: str  # "terminal", "fork", "continue", "prune"
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
        self.blocks_that_can_reach_call, self.block_distances = self._precompute_reachability(cfg)

    def _flatten_cfg(self, cfg: ControlFlowGraph) -> Dict[int, Instruction]:
        """
        Creates a PC -> Instruction mapping from two authoritative sources:

        1. ``cfg.blocks`` — the original-bytecode instructions produced by
           BytecodeAnalysisEngine.  Their PCs are unaffected by the byte-offset
           shifts that _assemble_instrumented introduces when it injects redirect
           stubs at every indirect-JUMP site (replacing 1 byte with 3-4 bytes
           shifts every subsequent PC).  Using the CFG directly ensures that
           PC=746, PC=778, etc. map to their correct JUMPDEST instructions rather
           than landing inside a PUSH operand of the shifted instrumented stream.

        2. pyevmasm disassembly of ``self.bytecode[BRANCH_TABLE_OFFSET:]`` — the
           branch-table (0xE000) and intermediate gadgets (0xF000) that were
           appended by _assemble_instrumented and do NOT exist in the original
           CFG.  Each pc is rebased by adding BRANCH_TABLE_OFFSET.
        """
        import pyevmasm

        instrs: Dict[int, Instruction] = {}

        # ── Source 1: CFG blocks (original, shift-free bytecode PCs) ─────────
        for block in cfg.blocks.values():
            for instr in block.instructions:
                instrs[instr.pc] = instr

        # ── Source 2: Branch-table + intermediate gadgets (0xE000 onwards) ───
        if len(self.bytecode) > BRANCH_TABLE_OFFSET:
            branch_region = self.bytecode[BRANCH_TABLE_OFFSET:]
            for jinstr in pyevmasm.disassemble_all(branch_region):
                operand = jinstr.operand
                if isinstance(operand, int):
                    operand_size = jinstr.size - 1
                    if operand_size > 0:
                        operand = operand.to_bytes(operand_size, "big")
                    else:
                        operand = None
                pc = BRANCH_TABLE_OFFSET + jinstr.pc
                instrs[pc] = Instruction(
                    pc=pc,
                    opcode=jinstr.opcode,
                    mnemonic=jinstr.mnemonic,
                    operand=operand,
                    size=jinstr.size,
                )

        return instrs

    def _precompute_reachability(self, cfg: ControlFlowGraph) -> Tuple[Set[int], Dict[int, int]]:
        """
        Uses reverse BFS from CALL blocks to identify all blocks that can reach a CALL.
        Returns a set of block start_pcs and a dictionary of distances to the nearest CALL.
        """
        call_opcodes = {0xf1, 0xf2, 0xf4, 0xfa} # CALL, CALLCODE, DELEGATECALL, STATICCALL
        call_blocks = []
        for pc, block in cfg.blocks.items():
            if any(instr.opcode in call_opcodes for instr in block.instructions):
                call_blocks.append(pc)
        
        if not call_blocks:
            return set(), {}

        # Reverse BFS
        reachable = set()
        distances = {}
        queue = deque([(pc, 0) for pc in call_blocks])
        
        while queue:
            pc, d = queue.popleft()
            if pc in reachable and distances[pc] <= d:
                continue
                
            reachable.add(pc)
            distances[pc] = d
            
            block = cfg.blocks.get(pc)
            if block:
                for pred in block.predecessors:
                    if pred not in reachable or distances.get(pred, float('inf')) > d + 1:
                        queue.append((pred, d + 1))
                        
        return reachable, distances

    def execute(self, initial_state: SymbolicState) -> List[SymbolicState]:
        """Explores paths using DFS."""
        traces: List[SymbolicState] = []
        worklist: List[SymbolicState] = [initial_state]
        paths_explored = 0
        start_time = time.time()

        logger.info(f"Starting symbolic execution at PC {initial_state.pc}")

        stats = {
            "completed": 0,
            "pruned_unsat": 0,
            "pruned_depth": 0,
            "pruned_branch_table": 0,
            "pruned_invalid_jump": 0,
            "pruned_empty_block": 0,
            "pruned_other": 0,
            "worklist_empty": 0,
        }

        while worklist and paths_explored < self.config.max_symbolic_paths:
            if time.time() - start_time > self.config.timeout_per_contract:
                logger.warning("Symbolic execution timeout reached")
                break

            state = worklist.pop()

            # DFS exploration
            result = self._execute_path(state)
            if result.type == "terminal":
                traces.append(state)
                stats["completed"] += 1
                paths_explored += 1
            elif result.type == "fork":
                # Add feasible paths to worklist
                for s in reversed(result.states):
                    if s.is_feasible():
                        worklist.append(s)
                    else:
                        stats["pruned_unsat"] += 1
            elif result.type == "continue":
                worklist.append(result.states[0])
            elif result.type == "prune":
                reason = result.reason.lower()
                if "depth" in reason:
                    stats["pruned_depth"] += 1
                elif "branch table" in reason:
                    stats["pruned_branch_table"] += 1
                elif "jump" in reason:
                    stats["pruned_invalid_jump"] += 1
                elif "instruction" in reason:
                    stats["pruned_empty_block"] += 1
                else:
                    stats["pruned_other"] += 1
                traces.append(state)

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
                state.pc = next_pc  # Record final PC
                return ExecutionResult.terminal()

            if op == OP_JUMP:
                if not state.stack:
                    return ExecutionResult.prune("Stack underflow at JUMP")
                dest = state.stack.pop()
                if isinstance(dest, int):
                    # Real EVM reverts if the destination is not a JUMPDEST.
                    # Guard here so stale stack values (e.g. 0x20 pushed as a
                    # memory offset) don't silently land on operand bytes and
                    # produce a misleading pruned_empty_block count.
                    if dest not in self.disassembly:
                        return ExecutionResult.prune(
                            f"Invalid JUMP to PC={dest}: not a valid instruction"
                        )
                    state.pc = dest
                    continue
                else:
                    # Symbolic destination — route through the branch table so the
                    # deobfuscator can fork into every concrete JUMPDEST candidate.
                    # The branch table's first opcode (DUP1) expects the symbolic
                    # destination to be on top of the stack when we arrive.
                    if BRANCH_TABLE_OFFSET in self.disassembly:
                        state.stack.append(dest)  # restore dest for branch-table DUP1
                        state.pc = BRANCH_TABLE_OFFSET
                        continue
                    return ExecutionResult.prune("Symbolic JUMP destination")

            if op == OP_JUMPI:
                if len(state.stack) < 2:
                    return ExecutionResult.prune("Stack underflow at JUMPI")
                dest = state.stack.pop()
                condition = state.stack.pop()

                if isinstance(dest, int):
                    # Real EVM reverts if the JUMPI destination is not a JUMPDEST.
                    if dest not in self.disassembly:
                        return ExecutionResult.prune(
                            f"Invalid JUMPI to PC={dest}: not a valid instruction"
                        )

                    # Fork
                    z3_condition = self._to_z3(condition)

                    taken = state.fork(z3_condition != 0)
                    taken.pc = dest

                    fallthrough = state.fork(z3_condition == 0)
                    fallthrough.pc = next_pc

                    # Branch table visit count (pruning rule)
                    if dest == BRANCH_TABLE_OFFSET:
                        taken.branch_table_visits += 1
                        if (
                            taken.branch_table_visits
                            > self.config.branch_table_max_visits
                        ):
                            return ExecutionResult.continue_(fallthrough)

                    return ExecutionResult.fork(taken, fallthrough)
                else:
                    # Symbolic destination — the fallthrough (condition==0) stays at
                    # next_pc; the taken fork (condition!=0) is routed through the
                    # branch table which will fork once per concrete JUMPDEST.
                    if BRANCH_TABLE_OFFSET in self.disassembly:
                        z3_condition = self._to_z3(condition)

                        fallthrough = state.fork(z3_condition == 0)
                        fallthrough.pc = next_pc

                        taken = state.fork(z3_condition != 0)
                        taken.stack.append(dest)  # restore dest for branch-table DUP1
                        taken.pc = BRANCH_TABLE_OFFSET
                        taken.branch_table_visits += 1
                        if (
                            taken.branch_table_visits
                            > self.config.branch_table_max_visits
                        ):
                            return ExecutionResult.continue_(fallthrough)

                        return ExecutionResult.fork(taken, fallthrough)
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
            val = int.from_bytes(instr.operand if instr.operand else b"", "big")
            state.stack.append(val)
            return True

        # DUPx
        if 0x80 <= op <= 0x8F:
            idx = op - 0x80 + 1
            if len(state.stack) < idx:
                return False
            state.stack.append(state.stack[-idx])
            return True

        # SWAPx
        if 0x90 <= op <= 0x9F:
            idx = op - 0x90 + 1
            if len(state.stack) < idx + 1:
                return False
            state.stack[-1], state.stack[-idx - 1] = (
                state.stack[-idx - 1],
                state.stack[-1],
            )
            return True

        # Simple Arithmetic & Bitwise
        if op in (
            OP_ADD,
            OP_MUL,
            OP_SUB,
            OP_DIV,
            OP_AND,
            OP_OR,
            OP_XOR,
            OP_SHL,
            OP_SHR,
            OP_SAR,
        ):
            if len(state.stack) < 2:
                return False
            a = state.stack.pop()
            b = state.stack.pop()

            # ── Concrete short-circuit ──────────────────────────────────────
            # When both operands are plain Python ints (no symbolic taint),
            # evaluate immediately to a concrete int.  This is critical for
            # selector computation chains like PUSH4 <sel>; PUSH1 0xe0; SHL
            # which must resolve to a known int so _is_risky_selector can
            # match against the ERC-20 selector table.
            _M256 = (1 << 256) - 1
            if isinstance(a, int) and isinstance(b, int):
                if op == OP_ADD:
                    concrete = (a + b) & _M256
                elif op == OP_MUL:
                    concrete = (a * b) & _M256
                elif op == OP_SUB:
                    concrete = (a - b) & _M256
                elif op == OP_DIV:
                    concrete = (b // a) if a != 0 else 0
                elif op == OP_AND:
                    concrete = a & b
                elif op == OP_OR:
                    concrete = a | b
                elif op == OP_XOR:
                    concrete = a ^ b
                elif op == OP_SHL:
                    # EVM SHL: shift=a (top), value=b; result = b << a  (mod 2^256)
                    concrete = (b << a) & _M256 if a < 256 else 0
                elif op == OP_SHR:
                    # Logical (unsigned) right shift
                    concrete = (b >> a) if a < 256 else 0
                elif op == OP_SAR:
                    # Arithmetic (signed) right shift
                    if a >= 256:
                        concrete = _M256 if b >> 255 else 0
                    else:
                        signed_b = b if b < (1 << 255) else b - (1 << 256)
                        concrete = signed_b >> a
                        concrete = concrete & _M256
                else:
                    concrete = 0
                state.stack.append(concrete)
                return True
            # ── Symbolic path ───────────────────────────────────────────────

            res_name = f"res_{instr.pc}_{len(state.path_constraints)}"
            res = z3.BitVec(res_name, 256)

            if op == OP_ADD:
                state.path_constraints.append(res == (self._to_z3(a) + self._to_z3(b)))
            elif op == OP_SUB:
                state.path_constraints.append(res == (self._to_z3(a) - self._to_z3(b)))
            elif op == OP_AND:
                state.path_constraints.append(res == (self._to_z3(a) & self._to_z3(b)))
            elif op == OP_OR:
                state.path_constraints.append(res == (self._to_z3(a) | self._to_z3(b)))
            elif op == OP_XOR:
                state.path_constraints.append(res == (self._to_z3(a) ^ self._to_z3(b)))
            elif op == OP_SHL:
                state.path_constraints.append(res == (self._to_z3(b) << self._to_z3(a)))
            elif op == OP_SHR:
                state.path_constraints.append(
                    res == z3.LShR(self._to_z3(b), self._to_z3(a))
                )
            elif op == OP_SAR:
                state.path_constraints.append(res == (self._to_z3(b) >> self._to_z3(a)))

            # Taint propagation
            if state.taint_map.is_tainted(a) or state.taint_map.is_tainted(b):
                state.taint_map.mark_tainted(res, "derived")

            state.stack.append(res)
            return True

        # Comparisons
        if op in (OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO):
            if op == OP_ISZERO:
                if not state.stack:
                    return False
                a = state.stack.pop()
                res = z3.BitVec(f"iszero_{instr.pc}_{len(state.path_constraints)}", 256)
                state.path_constraints.append(
                    res
                    == z3.If(
                        self._to_z3(a) == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)
                    )
                )

                if state.taint_map.is_tainted(a):
                    state.taint_map.mark_tainted(res, "derived")

                state.stack.append(res)
                return True

            if len(state.stack) < 2:
                return False
            a = state.stack.pop()
            b = state.stack.pop()
            res = z3.BitVec(f"cmp_{instr.pc}_{len(state.path_constraints)}", 256)

            cond = None
            if op == OP_LT:
                cond = z3.ULT(self._to_z3(a), self._to_z3(b))
            elif op == OP_GT:
                cond = z3.UGT(self._to_z3(a), self._to_z3(b))
            elif op == OP_SLT:
                cond = self._to_z3(a) < self._to_z3(b)
            elif op == OP_SGT:
                cond = self._to_z3(a) > self._to_z3(b)
            elif op == OP_EQ:
                cond = self._to_z3(a) == self._to_z3(b)

            if cond is not None:
                state.path_constraints.append(
                    res == z3.If(cond, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))
                )

            if state.taint_map.is_tainted(a) or state.taint_map.is_tainted(b):
                state.taint_map.mark_tainted(res, "derived")

            state.stack.append(res)
            return True

        if op == OP_CALLDATASIZE:
            sym_size = z3.BitVec(f"calldata_size_{instr.pc}", 256)
            state.path_constraints.append(sym_size >= 4)  # Assume at least a selector
            state.stack.append(sym_size)
            return True

        if op == OP_CALLDATALOAD:
            if not state.stack:
                return False
            offset = state.stack.pop()
            # Standardized naming: calldata_{pc}_{offset}
            # This allows the synthesizer to know exactly which byte this variable represents.
            if isinstance(offset, int):
                name = f"calldata_{instr.pc}_{offset}"
            else:
                name = f"calldata_{instr.pc}_sym_{len(state.path_constraints)}"
            
            sym_val = z3.BitVec(name, 256)
            state.taint_map.mark_tainted(
                sym_val, "calldata", offset if isinstance(offset, int) else None
            )
            state.stack.append(sym_val)
            return True

        if op == OP_CALLDATACOPY:
            if len(state.stack) < 3:
                return False
            destOffset = state.stack.pop()
            offset = state.stack.pop()
            length = state.stack.pop()

            # Simplified CALLDATACOPY: map calldata variables to memory 32-byte chunks
            if (
                isinstance(length, int)
                and isinstance(destOffset, int)
                and isinstance(offset, int)
            ):
                for i in range(0, length, 32):
                    chunk_offset = offset + i
                    mem_offset = destOffset + i
                    # Standardized naming matches synthesizer's parser
                    sym_val = z3.BitVec(
                        f"calldata_{instr.pc}_{chunk_offset}", 256
                    )
                    state.taint_map.mark_tainted(sym_val, "calldata", chunk_offset)
                    state.memory[mem_offset] = sym_val
            return True

        if op in (OP_CALL, OP_STATICCALL, OP_DELEGATECALL, OP_CALLCODE):
            if op in (OP_CALL, OP_CALLCODE):
                if len(state.stack) < 7:
                    return False
                gas = state.stack.pop()
                to = state.stack.pop()
                val = state.stack.pop()
                in_off = state.stack.pop()
                in_size = state.stack.pop()
                out_off = state.stack.pop()
                out_size = state.stack.pop()
            else:  # STATICCALL, DELEGATECALL
                if len(state.stack) < 6:
                    return False
                gas = state.stack.pop()
                to = state.stack.pop()
                val = 0  # No value for static/delegate
                in_off = state.stack.pop()
                in_size = state.stack.pop()
                out_off = state.stack.pop()
                out_size = state.stack.pop()

            encounter = CallEncounter(
                pc=instr.pc,
                gas=gas,
                target_address=to,
                value=val,
                args_offset=in_off,
                args_size=in_size,
            )

            # Try to extract function selector and arguments from memory
            # Note: This assumes standard ABI calldata layout
            if isinstance(in_off, int):
                # Standard ABI: Word 0 has selector. Arg1 starts at +4, Arg2 at +36.
                # However, if memory is word-aligned at in_off, they might be at +32, +64.
                # Heuristic: pick the first one that exists and is tainted.
                
                # Selector is at in_off (top 4 bytes usually)
                encounter.function_selector = state.memory.get(in_off, None)
                
                # Arg1 (Recipient): check standard offset +4 first, then aligned +32
                arg1_candidates = [in_off + 4, in_off + 32]
                for cand in arg1_candidates:
                    val = state.memory.get(cand, None)
                    if val is not None:
                        encounter.arg1_recipient = val
                        if state.taint_map.is_tainted(val):
                            break # Found it

                # Arg2 (Amount): check standard +36 first, then aligned +64
                arg2_candidates = [in_off + 36, in_off + 64]
                for cand in arg2_candidates:
                    val = state.memory.get(cand, None)
                    if val is not None:
                        encounter.arg2_amount = val
                        if state.taint_map.is_tainted(val):
                            break

            encounter.taint.target_tainted = state.taint_map.is_tainted(to)
            encounter.taint.args_tainted = state.taint_map.is_tainted(in_off)

            # Save constraints for this specific call point
            encounter.path_constraints = [c for c in state.path_constraints]

            state.calls_encountered.append(encounter)
            state.stack.append(1)  # Assume success
            return True

        if op == OP_POP:
            if state.stack:
                state.stack.pop()
            return True

        if op == OP_MLOAD:
            if not state.stack:
                return False
            offset = state.stack.pop()
            # Simplified memory: Dict[int, Union[z3.BitVecRef, int]]
            # Real EVM memory is byte-addressed.
            val = state.memory.get(
                offset if isinstance(offset, int) else str(offset), 0
            )

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
            if len(state.stack) < 2:
                return False
            offset = state.stack.pop()
            value = state.stack.pop()
            state.memory[offset if isinstance(offset, int) else str(offset)] = value
            return True

        if op == OP_MSTORE8:
            if len(state.stack) < 2:
                return False
            offset = state.stack.pop()
            value = state.stack.pop()
            # Simplified: MSTORE8 treated like MSTORE for now
            state.memory[offset if isinstance(offset, int) else str(offset)] = value
            return True

        if op == OP_SLOAD:
            if not state.stack:
                return False
            slot = state.stack.pop()
            key = slot if isinstance(slot, int) else str(slot)
            val = state.storage.get(key, None)
            if val is None:
                # Always create a symbolic value for any slot not yet written.
                # This covers both concrete slots (e.g. EIP-1967 implementation
                # slot) and symbolic slots.  Mark with source="storage" so the
                # VulnerabilityOracle can detect storage-controlled targets.
                val = z3.BitVec(
                    f"storage_{instr.pc}_{len(state.path_constraints)}", 256
                )
                state.storage[key] = val
                state.taint_map.mark_tainted(val, "storage")
            state.stack.append(val)
            return True

        if op == OP_SSTORE:
            if len(state.stack) < 2:
                return False
            slot = state.stack.pop()
            value = state.stack.pop()
            state.storage[slot if isinstance(slot, int) else str(slot)] = value
            return True

        if op == OP_JUMPDEST:
            return True

        # ── Push-only environment opcodes (pop 0, push 1 symbolic) ──────────
        if op in (
            OP_GAS,  # remaining gas
            OP_MSIZE,  # current memory size in bytes
            OP_ADDRESS,  # current contract address
            OP_SELFBALANCE,
            OP_ORIGIN,  # tx.origin
            OP_GASPRICE,
            OP_COINBASE,
            OP_TIMESTAMP,
            OP_NUMBER,
            OP_PREVRANDAO,
            OP_GASLIMIT,
            OP_CHAINID,
            OP_BASEFEE,
            OP_CODESIZE,
            OP_RETURNDATASIZE,
        ):
            mnemonic = OPCODE_TABLE.get(op, f"op_{op:02x}")
            sym = z3.BitVec(f"env_{mnemonic}_{instr.pc}", 256)
            state.stack.append(sym)
            return True

        # OP_PC — push the literal program counter value (known at compile time)
        if op == OP_PC:
            state.stack.append(instr.pc)
            return True

        # ── Pop 1, push 1 ────────────────────────────────────────────────────
        if op in (OP_BALANCE, OP_EXTCODESIZE, OP_EXTCODEHASH, OP_BLOCKHASH):
            if not state.stack:
                return False
            arg = state.stack.pop()
            sym = z3.BitVec(f"env_{OPCODE_TABLE.get(op, hex(op))}_{instr.pc}", 256)
            if state.taint_map.is_tainted(arg):
                state.taint_map.mark_tainted(sym, "derived")
            state.stack.append(sym)
            return True

        # ── Unary bitwise NOT ────────────────────────────────────────────────
        if op == OP_NOT:
            if not state.stack:
                return False
            a = state.stack.pop()
            res = z3.BitVec(f"not_{instr.pc}_{len(state.path_constraints)}", 256)
            state.path_constraints.append(res == ~self._to_z3(a))
            if state.taint_map.is_tainted(a):
                state.taint_map.mark_tainted(res, "derived")
            state.stack.append(res)
            return True

        # ── KECCAK256 (pop offset + size, push symbolic hash) ────────────────
        if op == OP_KECCAK256:
            if len(state.stack) < 2:
                return False
            _offset = state.stack.pop()
            _size = state.stack.pop()
            sym = z3.BitVec(f"keccak_{instr.pc}_{len(state.path_constraints)}", 256)
            state.stack.append(sym)
            return True

        # ── Binary ops not yet in the main handler (pop 2, push 1) ──────────
        if op in (OP_MOD, OP_SDIV, OP_SMOD, OP_EXP, OP_SIGNEXTEND, OP_BYTE):
            if len(state.stack) < 2:
                return False
            a = state.stack.pop()
            b = state.stack.pop()
            sym = z3.BitVec(f"binop_{instr.pc}_{len(state.path_constraints)}", 256)
            if state.taint_map.is_tainted(a) or state.taint_map.is_tainted(b):
                state.taint_map.mark_tainted(sym, "derived")
            state.stack.append(sym)
            return True

        # ── Ternary ops (pop 3, push 1) ──────────────────────────────────────
        if op in (OP_ADDMOD, OP_MULMOD):
            if len(state.stack) < 3:
                return False
            a = state.stack.pop()
            b = state.stack.pop()
            c = state.stack.pop()
            sym = z3.BitVec(f"ternop_{instr.pc}_{len(state.path_constraints)}", 256)
            if any(state.taint_map.is_tainted(x) for x in (a, b, c)):
                state.taint_map.mark_tainted(sym, "derived")
            state.stack.append(sym)
            return True

        # ── Contract creation (pop 3/4, push new address) ────────────────────
        if op == OP_CREATE:
            if len(state.stack) < 3:
                return False
            for _ in range(3):
                state.stack.pop()
            sym = z3.BitVec(f"created_addr_{instr.pc}", 256)
            state.stack.append(sym)
            return True

        if op == OP_CREATE2:
            if len(state.stack) < 4:
                return False
            for _ in range(4):
                state.stack.pop()
            sym = z3.BitVec(f"created2_addr_{instr.pc}", 256)
            state.stack.append(sym)
            return True

        # ── Memory copy opcodes (pop 3, push nothing) ────────────────────────
        if op in (OP_CODECOPY, OP_RETURNDATACOPY):
            if len(state.stack) < 3:
                return False
            for _ in range(3):
                state.stack.pop()
            return True

        if op == OP_EXTCODECOPY:
            if len(state.stack) < 4:
                return False
            for _ in range(4):
                state.stack.pop()
            return True

        # ── LOG0..LOG4 (pop 2+N, push nothing) ──────────────────────────────
        if OP_LOG0 <= op <= OP_LOG4:
            n_topics = op - OP_LOG0
            total_pops = 2 + n_topics  # offset, size, [topic0..topicN]
            if len(state.stack) < total_pops:
                return False
            for _ in range(total_pops):
                state.stack.pop()
            return True

        # Default: unknown opcode — step over without modifying stack
        return True

    def _to_z3(self, val: Union[z3.BitVecRef, int]) -> z3.BitVecRef:
        if isinstance(val, int):
            return z3.BitVecVal(val, 256)
        if isinstance(val, z3.BoolRef):
            return z3.If(val, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))
        return val
