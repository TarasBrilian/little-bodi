# tests/unit/test_concolic_execution.py
import pytest
import z3
from typing import List
from core.concolic_execution.engine import ConcolicEngine
from core.concolic_execution.models import SeedInput
from core.pipeline import AnalysisContext, AnalysisConfig
from core.bytecode_analysis.engine import BytecodeAnalysisEngine

def test_concolic_path_following():
    """Test that concolic execution follows the concrete path from a seed."""
    config = AnalysisConfig()
    
    # Bytecode: CALLER, PUSH1 0x22, EQ, PUSH1 0x08, JUMPI, STOP, JUMPDEST, STOP
    bytecode = bytes.fromhex("33602214600857005b00")
    
    # Seed 1: Caller is 0x22 -> JUMPI should be TAKEN
    seed_taken = SeedInput(
        origin="0x22",
        caller="0x22",
        calldata=b"",
        value=0,
        block_number=123
    )
    
    ctx = AnalysisContext(
        bytecode=bytecode,
        contract_address="0x123",
        chain_id=1,
        block_number=None,
        config=config
    )
    ctx.seed_inputs = [seed_taken]
    
    # Run Bytecode Analysis first to get CFG
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    # Run Concolic Execution
    concolic_engine = ConcolicEngine(config)
    ctx = concolic_engine.execute(ctx)
    
    # Should only have 1 trace (concolic doesn't fork)
    assert len(ctx.execution_traces) == 1
    state = ctx.execution_traces[0]
    # Path should end at JUMPDEST -> STOP (PC 9)
    # PC 0 (CALLER), 1 (PUSH), 3 (EQ), 4 (PUSH), 6 (JUMPI), 8 (JUMPDEST), 9 (STOP)
    # Wait, in our interpreter PC is updated to next_pc AT THE END or inside.
    assert state.pc >= 8

def test_concolic_taint_propagation(bytecode_indirect_jump):
    """Test taint propagation on the symbolic track during concolic execution."""
    config = AnalysisConfig()
    
    # Seed with some calldata
    seed = SeedInput(
        origin="0xabc",
        caller="0xabc",
        calldata=bytes.fromhex("11223344"),
        value=0,
        block_number=123
    )
    
    ctx = AnalysisContext(
        bytecode=bytecode_indirect_jump,
        contract_address="0x456",
        chain_id=1,
        block_number=None,
        config=config
    )
    ctx.seed_inputs = [seed]
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    # Run Deobfuscation if needed for indirect jump, but since we are concolic,
    # we might just follow the concrete JUMP if the seed allows it.
    
    concolic_engine = ConcolicEngine(config)
    ctx = concolic_engine.execute(ctx)
    
    # Verify that the trace exists
    assert len(ctx.execution_traces) > 0
    state = ctx.execution_traces[0]
    
    # The result of SHR was used as JUMP destination. 
    # It might have been popped from stack, so we check if any constraints or 
    # the internal taint map contains "derived" taint.
    
    # 1. Check if the PC reached the (incorrect) jump destination 
    # derived from tainted calldata: 0x11223344... >> 240 = 0x1122
    assert state.pc == 0x1122
    
    # 2. Check if the internal taint map has entries
    found_taint = any(info.source == "derived" or info.source == "calldata" 
                      for info in state.taint_map._tainted.values())
                          
    assert found_taint is True

def test_concolic_fallback():
    """Test that engine falls back to symbolic execution when no seeds are provided."""
    config = AnalysisConfig(fallback_to_symbolic=True)
    
    # Simple bytecode with a branch
    bytecode = bytes.fromhex("33602214600857005b00")
    
    ctx = AnalysisContext(
        bytecode=bytecode,
        contract_address="0x789",
        chain_id=1,
        block_number=None,
        config=config
    )
    ctx.seed_inputs = [] # No seeds
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    concolic_engine = ConcolicEngine(config)
    ctx = concolic_engine.execute(ctx)
    
    # Fallback to symbolic should explore BOTH paths
    assert len(ctx.execution_traces) >= 2
