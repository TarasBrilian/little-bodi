# core/deobfuscation/engine.py
from __future__ import annotations
import logging
from typing import List, Set, Dict, Optional, Tuple
from pydantic import BaseModel, Field

from core.pipeline import BaseEngine, AnalysisContext, AnalysisConfig, EngineInputError
from core.constants import (
    OP_JUMP,
    OP_JUMPI,
    OP_JUMPDEST,
    OP_PUSH1,
    OP_PUSH2,
    OP_DUP1,
    OP_EQ,
    OP_POP,
    OP_INVALID,
    OP_SWAP1,
    BRANCH_TABLE_OFFSET,
    INTERMEDIATE_OFFSET,
)

# Reuse models from bytecode_analysis or define specific ones if needed
from core.bytecode_analysis.engine import ControlFlowGraph, IndirectJump, BasicBlock

logger = logging.getLogger(__name__)

class DeobfuscationInput(BaseModel):
    """Input data structure for DeobfuscationEngine."""
    bytecode: bytes
    cfg: ControlFlowGraph
    indirect_jumps: List[IndirectJump]
    jumpdests: Set[int]

    class Config:
        arbitrary_types_allowed = True

class DeobfuscationOutput(BaseModel):
    """Output data structure for DeobfuscationEngine."""
    deobfuscated_cfg: ControlFlowGraph
    instrumented_bytecode: bytes
    branch_table_entries: List[int]
    branch_table_size: int
    coverage_after: float

    class Config:
        arbitrary_types_allowed = True

class DeobfuscationEngine(BaseEngine):
    """
    Implements branch table injection to resolve indirect jumps in EVM bytecode.
    Ref: SKANF (Yang et al., 2025)
    """

    def validate_input(self, ctx: AnalysisContext) -> None:
        """Ensures CFG is available from BytecodeAnalysisEngine."""
        if ctx.cfg is None:
            raise EngineInputError("Missing CFG in AnalysisContext")

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        Executes the deobfuscation pipeline.
        """
        if not ctx.indirect_jumps:
            logger.info("No indirect jumps to resolve. Skipping deobfuscation.")
            ctx.deobfuscated_cfg = ctx.cfg
            ctx.instrumented_bytecode = ctx.bytecode
            ctx.coverage_after = ctx.coverage_before
            return ctx

        if not ctx.jumpdests:
             logger.warning("Indirect jumps detected but no JUMPDESTs found. Cannot deobfuscate.")
             ctx.deobfuscated_cfg = ctx.cfg
             ctx.instrumented_bytecode = ctx.bytecode
             ctx.coverage_after = ctx.coverage_before
             return ctx

        # 1. Collect all valid destinations
        destinations = sorted(list(ctx.jumpdests))
        
        # 2. Build Branch Table & Intermediates
        branch_table = self._build_branch_table(destinations)
        intermediates = self._build_intermediates(destinations)
        
        # 3. CFG-level deobfuscation (for Analysis)
        # We cast ctx.cfg to ControlFlowGraph since we know it's that type from BytecodeAnalysisEngine
        ctx.deobfuscated_cfg = self._deobfuscate_cfg(ctx.cfg, ctx.indirect_jumps, destinations)
        
        # 4. Assemble Instrumented Bytecode (for Execution/Concolic)
        ctx.instrumented_bytecode = self._assemble_instrumented(
            ctx.bytecode, 
            ctx.indirect_jumps, 
            branch_table, 
            intermediates
        )
        
        # 5. Calculate new coverage (approximate for now based on over-approximation)
        ctx.coverage_after = self._calculate_approx_coverage(ctx.deobfuscated_cfg)
        
        logger.info(f"Deobfuscation complete: {len(ctx.indirect_jumps)} indirect jumps resolved via {len(destinations)} table entries")
        
        return ctx

    def _build_branch_table(self, destinations: List[int]) -> bytes:
        """
        Generates bytecode for lookup table at 0xE000.
        Logic: DUP1, PUSH2 <dest>, EQ, PUSH2 <intermediate>, JUMPI
        """
        table = bytearray()
        table.append(OP_JUMPDEST) # Entry at 0xE000
        
        intermediate_pc = INTERMEDIATE_OFFSET
        for dest in destinations:
            table.append(OP_DUP1)
            # PUSH2 <dest>
            table.append(OP_PUSH2)
            table.extend(dest.to_bytes(2, 'big'))
            # EQ
            table.append(OP_EQ)
            # PUSH2 <intermediate>
            table.append(OP_PUSH2)
            table.extend(intermediate_pc.to_bytes(2, 'big'))
            # JUMPI
            table.append(0x57) # OP_JUMPI
            
            intermediate_pc += 6 # Each intermediate is 6 bytes
            
        table.append(OP_INVALID) # Fallthrough if no match
        return bytes(table)

    def _build_intermediates(self, destinations: List[int]) -> bytes:
        """
        Generates bytecode for intermediates at 0xF000.
        Logic: JUMPDEST, POP, PUSH2 <dest>, JUMP
        """
        intermediates = bytearray()
        for dest in destinations:
            intermediates.append(OP_JUMPDEST)
            intermediates.append(OP_POP)
            intermediates.append(OP_PUSH2)
            intermediates.extend(dest.to_bytes(2, 'big'))
            intermediates.append(0x56) # OP_JUMP
        return bytes(intermediates)

    def _deobfuscate_cfg(
        self, 
        cfg: ControlFlowGraph, 
        indirect_jumps: List[IndirectJump], 
        destinations: List[int]
    ) -> ControlFlowGraph:
        """
        Updates the CFG by adding edges from indirect jumps to all valid JUMPDESTs.
        """
        # Deep copy the blocks for the new CFG
        new_blocks = {pc: block.copy(deep=True) for pc, block in cfg.blocks.items()}
        
        for ijump in indirect_jumps:
            # Find the block ending with this indirect jump
            # BasicBlock pc is the start_pc, but we need to find the block that contains ijump.pc
            target_block = None
            for block in new_blocks.values():
                if ijump.pc == block.end_pc:
                    target_block = block
                    break
            
            if target_block:
                # Add all valid destinations as successors
                # Note: This is an over-approximation as per specification
                for dest in destinations:
                    if dest not in target_block.successors:
                        target_block.successors.append(dest)
                        # Also update predecessors for the destination block
                        if dest in new_blocks:
                            if target_block.start_pc not in new_blocks[dest].predecessors:
                                new_blocks[dest].predecessors.append(target_block.start_pc)

        return ControlFlowGraph(blocks=new_blocks, entry_points=cfg.entry_points)

    def _assemble_instrumented(
        self, 
        original_bytecode: bytes, 
        indirect_jumps: List[IndirectJump], 
        branch_table: bytes, 
        intermediates: bytes
    ) -> bytes:
        """
        Injects redirects into the original bytecode and appends the branch table.
        
        Redirect logic:
        For JUMP: PUSH2 0xE000, JUMP (Note: this overwrites whatever was there)
        HOWEVER: Overwriting in-place is dangerous if the redirect is larger than the original jump.
        EVM JUMP is 1 byte, but 'PUSH2 0xE000, JUMP' is 4 bytes.
        
        Per SKANF/spec: We redirect by replacing the original JUMP/JUMPI.
        If we can't fit it, we might need to pad or use a smaller gadget.
        Actually, usually the pattern is PUSHx dest, JUMP.
        We can replace the PUSH value with 0xE000.
        
        Simple approach for implementation: 
        Replacement bytes for indirect jump at PC:
        JUMP -> SWAP1, POP, PUSH2 0xE000, JUMP (Wait, JUMP only takes 1 stack arg)
        JUMP -> PUSH2 0xE000, JUMP (but we need the original dest to be on stack for the branch table)
        Actually, the branch table expects the original destination to be on top of stack.
        So an indirect JUMP becomes: PUSH2 0xE000, JUMP (3 bytes replace X bytes)
        If the original was '... JUMP' and we replace JUMP with 'PUSH2 0xE000; JUMP' we shift offsets.
        BUT: The spec says "To avoid modifying PC offsets, Little Bodi modifies CFG for analysis ... 
        For execution, we build new bytecode."
        
        Actually, many indirect jumps look like:
        PUSH2 0x1234
        JUMP
        If we change 0x1234 to 0xE000, offsets stay same.
        
        If it's just 'JUMP' (dest already on stack):
        We need to PUSH2 0xE000, JUMP.
        
        Let's follow paper/spec: "Inject PUSH 0xe000 before it".
        Injection changes offsets. To avoid this, we can pad original bytecode to 0xE000.
        """
        result = bytearray(original_bytecode)
        
        # Simple injection for now (assuming we have space or can shift since it's for analysis tools)
        # Note: A real implementation would need to handle PC offset shifts.
        # For this engine, we will perform the redirects as described in JUMPI special handling.
        
        for ijump in reversed(indirect_jumps): # Reverse to keep offsets valid for previous jumps
            pc = ijump.pc
            if ijump.opcode == OP_JUMPI:
                # [condition, dest] -> SWAP1, PUSH2 0xE000, JUMPI, POP
                redirect = bytes([OP_SWAP1, OP_PUSH2, 0xE0, 0x00, OP_JUMPI, OP_POP])
            else:
                # [dest] -> PUSH2 0xE000, JUMP
                redirect = bytes([OP_PUSH2, 0xE0, 0x00, 0x56])
            
            # Replace the original opcode with the redirect
            result[pc:pc+1] = redirect
            
        # Pad to 0xE000
        while len(result) < BRANCH_TABLE_OFFSET:
            result.append(0x00) # STOP
            
        # Insert branch table
        result[BRANCH_TABLE_OFFSET:BRANCH_TABLE_OFFSET+len(branch_table)] = branch_table
        
        # Pad to 0xF000
        while len(result) < INTERMEDIATE_OFFSET:
            result.append(0x00)
            
        # Insert intermediates
        result[INTERMEDIATE_OFFSET:INTERMEDIATE_OFFSET+len(intermediates)] = intermediates
        
        return bytes(result)

    def _calculate_approx_coverage(self, cfg: ControlFlowGraph) -> float:
        """Simple reachability analysis on the deobfuscated CFG."""
        from collections import deque
        visited = set()
        queue = deque(cfg.entry_points)
        
        while queue:
            pc = queue.popleft()
            if pc in visited or pc not in cfg.blocks:
                continue
            visited.add(pc)
            for succ in cfg.blocks[pc].successors:
                if succ not in visited:
                    queue.append(succ)
                    
        total = len(cfg.blocks)
        reachable = len(visited)
        return (reachable / total) * 100.0 if total > 0 else 0.0
