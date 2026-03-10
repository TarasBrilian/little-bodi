import pytest
import z3
from core.symbolic_execution.engine import SymbolicExecutionEngine
from core.symbolic_execution.state import SymbolicState
from core.bytecode_analysis.engine import BytecodeAnalysisEngine, AnalysisContext, AnalysisConfig

def test_symbolic_taint_propagation(bytecode_indirect_jump):
    """Test that CALLDATALOAD produces tainted symbolic values and propagation works."""
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_indirect_jump,
        contract_address="0x123",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    # Run Bytecode Analysis
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    # Run Deobfuscation (Required for symbolic jumps)
    from core.deobfuscation.engine import DeobfuscationEngine
    deobf_engine = DeobfuscationEngine(config)
    ctx = deobf_engine.execute(ctx)
    
    # Run Symbolic Execution
    symbolic_engine = SymbolicExecutionEngine(config)
    ctx = symbolic_engine.execute(ctx)
    
    assert len(ctx.execution_traces) > 0
    # Check that at least one trace has encounter with calldata taint
    found_taint = False
    for state in ctx.execution_traces:
        if any(state.taint_map.is_tainted(val) for val in state.stack):
            found_taint = True
            break
    # Note: in indirect_jump.hex:
    # 600035 -> CALLDATALOAD (tainted)
    # 60f01c -> SHR (propagate taint)
    assert found_taint is True

def test_path_forking_jumpi():
    """Test that JUMPI creates two feasible paths."""
    config = AnalysisConfig()
    # CALLER, PUSH1 0x22, EQ, PUSH1 0x08, JUMPI, STOP, JUMPDEST, STOP
    bytecode_fork = bytes.fromhex("33602214600857005b00")
    
    ctx = AnalysisContext(
        bytecode=bytecode_fork,
        contract_address="0x456",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    symbolic_engine = SymbolicExecutionEngine(config)
    ctx = symbolic_engine.execute(ctx)
    
    # This should fork into two paths: one taken to JUMPDEST, one fallthrough to STOP
    assert len(ctx.execution_traces) >= 2

def test_symbolic_call_encounter(bytecode_vulnerable_transfer):
    """Test that CALL instructions are recorded with correct context."""
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_vulnerable_transfer,
        contract_address="0x789",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    symbolic_engine = SymbolicExecutionEngine(config)
    ctx = symbolic_engine.execute(ctx)
    
    assert len(ctx.potential_vulnerabilities) > 0
    enc = ctx.potential_vulnerabilities[0]
    assert enc.pc > 0
    # In vulnerable_transfer, the target/selector might be tainted
    assert enc.taint.target_tainted is True or enc.taint.args_tainted is True
