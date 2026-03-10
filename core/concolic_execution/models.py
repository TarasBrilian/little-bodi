# core/concolic_execution/models.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from core.bytecode_analysis.engine import ControlFlowGraph
from core.symbolic_execution.state import CallEncounter, SymbolicState

class SeedInput(BaseModel):
    """Represents a concrete transaction used as a seed for concolic execution."""
    origin: str
    caller: str
    calldata: bytes
    value: int
    block_number: int

class ConcolicConfig(BaseModel):
    max_seeds: int = 50
    timeout_per_seed: int = 120
    fallback_to_symbolic: bool = True
    max_symbolic_paths: int = 10000 # For fallback or mutated seeds

class ConcolicOutput(BaseModel):
    execution_traces: List[SymbolicState]
    seeds_used: int
    seeds_skipped: int
    fell_back_to_symbolic: bool
    vulnerability_hints: List[CallEncounter]

    class Config:
        arbitrary_types_allowed = True
