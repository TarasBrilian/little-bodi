# core/bytecode_analysis/engine.py
from __future__ import annotations
import logging
from typing import Optional, List, Set, Tuple, Dict
from pydantic import BaseModel, Field
from collections import deque

from core.pipeline import BaseEngine, AnalysisContext, AnalysisConfig, EngineInputError
from core.constants import (
    OPCODE_TABLE,
    BLOCK_TERMINATORS,
    OP_JUMP,
    OP_JUMPI,
    OP_JUMPDEST,
    TAINT_SOURCES,
)

logger = logging.getLogger(__name__)

# --- Data Models (Pydantic) ---

class Instruction(BaseModel):
    """Represents a single EVM instruction."""
    pc: int
    opcode: int
    mnemonic: str
    operand: Optional[bytes] = None
    size: int

    class Config:
        arbitrary_types_allowed = True

class BasicBlock(BaseModel):
    """Represents a sequence of instructions with one entry and one exit."""
    start_pc: int
    end_pc: int
    instructions: List[Instruction]
    successors: List[int] = Field(default_factory=list)
    predecessors: List[int] = Field(default_factory=list)
    is_reachable: bool = False

class ControlFlowGraph(BaseModel):
    """Represents the control flow of the bytecode."""
    blocks: Dict[int, BasicBlock] = Field(default_factory=dict)
    entry_points: List[int] = Field(default_factory=list)
    indirect_jumps: List[int] = Field(default_factory=list)

class IndirectJump(BaseModel):
    """Represents a jump instruction with a dynamic destination."""
    pc: int
    opcode: int
    stack_var: str
    depends_on: List[str] = Field(default_factory=list)

# --- Engine Implementation ---

class BytecodeAnalysisEngine(BaseEngine):
    """
    Analyzes EVM bytecode to produce an instruction list, CFG, and identify indirect jumps.
    """

    def validate_input(self, ctx: AnalysisContext) -> None:
        """Validates that bytecode is present and within size limits."""
        if not ctx.bytecode:
            raise EngineInputError("Empty bytecode")
        
        MAX_SIZE = 65536 
        if len(ctx.bytecode) > MAX_SIZE:
             raise EngineInputError(f"Bytecode exceeds analysis limit ({len(ctx.bytecode)} > {MAX_SIZE})")

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        Main execution logic: Disassembly -> CFG -> Indirect Jumps -> Coverage.
        """
        bytecode = ctx.bytecode
        
        # 1. Disassemble
        instructions, jumpdests, push_data_ranges = self.disassemble(bytecode)
        
        # 2. Build CFG
        cfg = self.build_cfg(instructions, jumpdests)
        
        # 3. Identify Indirect Jumps
        indirect_jumps = self.identify_indirect_jumps(cfg, instructions)
        
        # 4. Compute Coverage (Initial)
        coverage_before = self.compute_coverage(cfg)
        
        # Update context
        ctx.disassembly = instructions
        ctx.jumpdests = jumpdests
        ctx.cfg = cfg
        ctx.indirect_jumps = indirect_jumps
        ctx.coverage_before = coverage_before
        ctx.is_obfuscated = len(indirect_jumps) > 0
        
        return ctx

    def disassemble(self, bytecode: bytes) -> Tuple[List[Instruction], Set[int], List[Tuple[int, int]]]:
        """
        Correctly disassembles bytecode, skipping PUSH operands for JUMPDEST identification.
        """
        instructions: List[Instruction] = []
        jumpdests: Set[int] = set()
        push_data_ranges: List[Tuple[int, int]] = []
        
        i = 0
        while i < len(bytecode):
            pc = i
            opcode = bytecode[i]
            
            # PUSH1-PUSH32 (0x60-0x7F)
            if 0x60 <= opcode <= 0x7F:
                push_size = opcode - 0x5F
                operand_start = i + 1
                operand_end = i + 1 + push_size
                operand = bytecode[operand_start:operand_end]
                
                push_data_ranges.append((operand_start, operand_end))
                instr = Instruction(
                    pc=pc,
                    opcode=opcode,
                    mnemonic=f"PUSH{push_size}",
                    operand=operand,
                    size=1 + push_size
                )
                instructions.append(instr)
                i += 1 + push_size
            elif opcode == OP_JUMPDEST:
                jumpdests.add(pc)
                instructions.append(Instruction(
                    pc=pc, opcode=opcode, mnemonic="JUMPDEST", size=1
                ))
                i += 1
            else:
                mnemonic = OPCODE_TABLE.get(opcode, f"UNKNOWN_0x{opcode:02X}")
                instructions.append(Instruction(
                    pc=pc, opcode=opcode, mnemonic=mnemonic, size=1
                ))
                i += 1
                
        return instructions, jumpdests, push_data_ranges

    def build_cfg(self, instructions: List[Instruction], jumpdests: Set[int]) -> ControlFlowGraph:
        """
        Constructs a CFG by splitting instructions into basic blocks and determining edges.
        """
        if not instructions:
            return ControlFlowGraph()

        # Pass 1: Identify block boundary PCs
        block_starts: Set[int] = {instructions[0].pc}
        for i, instr in enumerate(instructions):
            if instr.opcode in BLOCK_TERMINATORS or instr.opcode == OP_JUMPI:
                if i + 1 < len(instructions):
                    block_starts.add(instructions[i+1].pc)
            if instr.opcode == OP_JUMPDEST:
                block_starts.add(instr.pc)

        # Pass 2: Create BasicBlocks
        sorted_starts = sorted(list(block_starts))
        blocks: Dict[int, BasicBlock] = {}
        for j, start in enumerate(sorted_starts):
            limit = sorted_starts[j+1] if j+1 < len(sorted_starts) else float('inf')
            block_instrs = [instr for instr in instructions if start <= instr.pc < limit]
            if not block_instrs:
                continue
            blocks[start] = BasicBlock(
                start_pc=start,
                end_pc=block_instrs[-1].pc,
                instructions=block_instrs
            )

        # Pass 3: Resolve edges
        for start, block in blocks.items():
            last_instr = block.instructions[-1]
            if last_instr.opcode == OP_JUMPI:
                # 1. Fall-through
                next_pc = last_instr.pc + last_instr.size
                if next_pc in blocks:
                    block.successors.append(next_pc)
                    if start not in blocks[next_pc].predecessors:
                        blocks[next_pc].predecessors.append(start)
                # 2. Taken
                target_pc = self._get_static_jump_target(block)
                if target_pc is not None and target_pc in jumpdests:
                    if target_pc in blocks:
                        block.successors.append(target_pc)
                        if start not in blocks[target_pc].predecessors:
                            blocks[target_pc].predecessors.append(start)
            elif last_instr.opcode == OP_JUMP:
                target_pc = self._get_static_jump_target(block)
                if target_pc is not None and target_pc in jumpdests:
                    if target_pc in blocks:
                        block.successors.append(target_pc)
                        if start not in blocks[target_pc].predecessors:
                            blocks[target_pc].predecessors.append(start)
            elif last_instr.opcode not in BLOCK_TERMINATORS:
                next_pc = last_instr.pc + last_instr.size
                if next_pc in blocks:
                    block.successors.append(next_pc)
                    if start not in blocks[next_pc].predecessors:
                        blocks[next_pc].predecessors.append(start)

        return ControlFlowGraph(blocks=blocks, entry_points=[instructions[0].pc])

    def _get_static_jump_target(self, block: BasicBlock) -> Optional[int]:
        """Heuristic: most jumps are preceded by a PUSH of the destination PC."""
        instrs = block.instructions
        if len(instrs) < 2:
            return None
        prev = instrs[-2]
        if 0x60 <= prev.opcode <= 0x7F and prev.operand:
            return int.from_bytes(prev.operand, byteorder='big')
        return None

    def identify_indirect_jumps(self, cfg: ControlFlowGraph, instructions: List[Instruction]) -> List[IndirectJump]:
        """Identifies jumps where the destination PC doesn't come from a static PUSH."""
        indirect = []
        for block in cfg.blocks.values():
            last = block.instructions[-1]
            if last.opcode in (OP_JUMP, OP_JUMPI):
                target = self._get_static_jump_target(block)
                if target is None:
                    deps = self._basic_backward_slice(block)
                    indirect.append(IndirectJump(
                        pc=last.pc,
                        opcode=last.opcode,
                        stack_var=f"dest_{last.pc:04x}",
                        depends_on=deps
                    ))
        return indirect

    def _basic_backward_slice(self, block: BasicBlock) -> List[str]:
        """Basic scan for potential sources of dynamic jump targets within the block."""
        deps = []
        for instr in block.instructions:
            if instr.opcode in TAINT_SOURCES:
                deps.append("calldata")
            elif instr.opcode == 0x54: # SLOAD
                deps.append("storage")
            elif instr.opcode == 0x51: # MLOAD
                deps.append("memory")
        return list(set(deps))

    def compute_coverage(self, cfg: ControlFlowGraph) -> float:
        """Determines % of reachable blocks via BFS."""
        if not cfg.blocks:
            return 0.0
        visited: Set[int] = set()
        queue = deque(cfg.entry_points)
        while queue:
            pc = queue.popleft()
            if pc in visited or pc not in cfg.blocks:
                continue
            visited.add(pc)
            block = cfg.blocks[pc]
            block.is_reachable = True
            for succ in block.successors:
                if succ not in visited:
                    queue.append(succ)
        total = len(cfg.blocks)
        reachable = len(visited)
        return (reachable / total) * 100.0 if total > 0 else 0.0
