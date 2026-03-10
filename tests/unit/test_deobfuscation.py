import pytest
from core.deobfuscation.engine import DeobfuscationEngine
from core.bytecode_analysis.engine import BytecodeAnalysisEngine, AnalysisContext, AnalysisConfig
from core.constants import BRANCH_TABLE_OFFSET, INTERMEDIATE_OFFSET

def test_deobfuscation_indirect_jump(bytecode_indirect_jump):
    """
    Test that DeobfuscationEngine correctly identifies and handles indirect jumps.
    """
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_indirect_jump,
        contract_address="0x123",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    # 1. Bytecode Analysis first
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    assert ctx.is_obfuscated is True
    assert len(ctx.indirect_jumps) > 0
    
    # 2. Deobfuscation
    deobf_engine = DeobfuscationEngine(config)
    ctx = deobf_engine.execute(ctx)
    
    # Verify results
    assert ctx.deobfuscated_cfg is not None
    assert ctx.instrumented_bytecode is not None
    assert len(ctx.instrumented_bytecode) >= INTERMEDIATE_OFFSET
    
    # Check for branch table at 0xE000
    assert ctx.instrumented_bytecode[BRANCH_TABLE_OFFSET] == 0x5B # JUMPDEST
    
    # Verify CFG edges were added
    # For each indirect jump, the block's successors should include all JUMPDESTs (over-approximation)
    for ijump in ctx.indirect_jumps:
        block = ctx.deobfuscated_cfg.blocks[ctx.cfg.blocks[0].start_pc] # Simplification for test
        # In the fixture, maybe there's only one block or we find the right one
        for b in ctx.deobfuscated_cfg.blocks.values():
            if b.end_pc == ijump.pc:
                assert len(b.successors) == len(ctx.jumpdests)
                break

def test_deobfuscation_coverage_improvement(bytecode_indirect_jump):
    """
    Test that deobfuscation improves (calculated) coverage.
    """
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_indirect_jump,
        contract_address="0x456",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    coverage_before = ctx.coverage_before
    
    deobf_engine = DeobfuscationEngine(config)
    ctx = deobf_engine.execute(ctx)
    
    assert ctx.coverage_after >= coverage_before

def test_deobfuscation_no_indirect_jumps(bytecode_safe):
    """
    Test that DeobfuscationEngine works correctly on non-obfuscated bytecode.
    """
    config = AnalysisConfig()
    ctx = AnalysisContext(
        bytecode=bytecode_safe,
        contract_address="0x789",
        chain_id=1,
        block_number=None,
        config=config
    )
    
    analysis_engine = BytecodeAnalysisEngine(config)
    ctx = analysis_engine.execute(ctx)
    
    assert ctx.is_obfuscated is False
    assert len(ctx.indirect_jumps) == 0
    
    deobf_engine = DeobfuscationEngine(config)
    ctx = deobf_engine.execute(ctx)
    
    # Should still work and produce results
    assert ctx.deobfuscated_cfg is not None
    assert ctx.instrumented_bytecode is not None
    assert ctx.coverage_after == ctx.coverage_before
