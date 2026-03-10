# tests/unit/test_bytecode_analysis.py
import pytest
from core.bytecode_analysis.engine import BytecodeAnalysisEngine
from core.pipeline import AnalysisContext, AnalysisConfig

def test_jumpdest_in_push_data_not_counted():
    """Byte 0x5B inside PUSH data is not a valid JUMPDEST."""
    # PUSH2 0x5B5B
    bytecode = bytes.fromhex("615B5B")
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode,
        contract_address=None,
        chain_id=1,
        block_number=None,
        config=config
    )
    engine = BytecodeAnalysisEngine(config)
    result_ctx = engine.run(ctx)
    
    assert 0x5B not in result_ctx.jumpdests
    assert len(result_ctx.cfg.blocks) == 1

def test_indirect_jump_detection(bytecode_indirect_jump):
    """JUMP with destination from CALLDATALOAD must be detected as indirect."""
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_indirect_jump,
        contract_address=None,
        chain_id=1,
        block_number=None,
        config=config
    )
    engine = BytecodeAnalysisEngine(config)
    result_ctx = engine.run(ctx)
    
    # 6000 35 60F0 1C 56 5B 00 5B F3
    # JUMP is at PC 4 (offset based on size of instructions)
    assert len(result_ctx.indirect_jumps) == 1
    assert "calldata" in result_ctx.indirect_jumps[0].depends_on
    assert result_ctx.is_obfuscated is True

def test_coverage_simple_jump():
    """A direct jump should result in 100% coverage if targets are valid."""
    # PUSH1 0x03, JUMP, STOP, JUMPDEST, STOP
    bytecode = bytes.fromhex("600456005B00")
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode,
        contract_address=None,
        chain_id=1,
        block_number=None,
        config=config
    )
    engine = BytecodeAnalysisEngine(config)
    result_ctx = engine.run(ctx)
    
    # 3 blocks: (0: PUSH1, JUMP), (3: STOP), (4: JUMPDEST, STOP)
    # PC 3 is unreachable because we jump from 2 to 4.
    # Coverage: 2/3 = 66.67%
    assert round(result_ctx.coverage_before, 2) == 66.67

def test_dead_code_coverage():
    """Unreachable code should reduce coverage."""
    # STOP, JUMPDEST, STOP (PC 1 is unreachable)
    bytecode = bytes.fromhex("005B00")
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode,
        contract_address=None,
        chain_id=1,
        block_number=None,
        config=config
    )
    engine = BytecodeAnalysisEngine(config)
    result_ctx = engine.run(ctx)
    
    # Block 1 starts at PC 0 (STOP)
    # Block 2 starts at PC 1 (JUMPDEST)
    assert result_ctx.coverage_before == 50.0

def test_push_disguised_fixture(bytecode_push_disguised):
    """Verify push_disguised.hex fixture results."""
    # Hex: 61 5B5B 6008 56 FE 5B 00
    # PC 0: 61 (PUSH2)
    # PC 1-2: 5B 5B (operands)
    # PC 3: 60 (PUSH1)
    # PC 4: 08 (operand)
    # PC 5: 56 (JUMP)
    # PC 6: FE (INVALID)
    # PC 7: 5B (JUMPDEST)
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_push_disguised,
        contract_address=None,
        chain_id=1,
        block_number=None,
        config=config
    )
    engine = BytecodeAnalysisEngine(config)
    result_ctx = engine.run(ctx)
    
    # Only PC 7 should be a JUMPDEST
    assert result_ctx.jumpdests == {7}
