# core/symbolic_execution/state.py
from __future__ import annotations
import z3
import copy
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union, Any
from pydantic import BaseModel

from core.constants import EVM_WORD_BITS

logger = logging.getLogger(__name__)

@dataclass
class TaintInfo:
    """Metadata about a tainted value."""
    source: str
    calldata_offset: Optional[int] = None

class TaintMap:
    """
    Tracks taint from calldata to values in stack/memory/storage.
    Conservative: if any part of an expression is tainted, the whole expression is tainted.
    """
    def __init__(self) -> None:
        self._tainted: Dict[str, TaintInfo] = {}

    def mark_tainted(self, value: z3.BitVecRef, source: str, offset: Optional[int] = None) -> None:
        """Marks a Z3 variable as tainted."""
        var_id = str(value)
        self._tainted[var_id] = TaintInfo(source=source, calldata_offset=offset)

    def is_tainted(self, value: Union[z3.BitVecRef, int, z3.ExprRef, bytes, None]) -> bool:
        """Checks if a value (or any constituent part) is tainted."""
        if value is None or isinstance(value, (int, bytes)):
            return False
        if not isinstance(value, z3.ExprRef):
            return False
        return self._check_tainted_recursive(value)

    def _check_tainted_recursive(self, expr: z3.ExprRef) -> bool:
        """Recursively checks Z3 expression for tainted sub-expressions."""
        if str(expr) in self._tainted:
            return True
        if hasattr(expr, "children"):
            for child in expr.children():
                if self._check_tainted_recursive(child):
                    return True
        return False

    def is_fully_controllable(self, value: Union[z3.BitVecRef, int, bytes, None], size_bytes: int = 32) -> bool:
        """
        Checks if a value is fully controllable by the adversary.
        Currently: if the value is directly a calldata BitVec or derived solely from it.
        """
        if value is None or isinstance(value, (int, bytes)):
            return False
            
        if not isinstance(value, z3.ExprRef):
            return False

        # Check if directly in taint map as calldata
        var_id = str(value)
        if var_id in self._tainted:
            info = self._tainted[var_id]
            if info.source == "calldata":
                return True
        
        # Recursive check: are all base variables in this expression from calldata?
        return self._is_derived_only_from_calldata(value)

    def _is_derived_only_from_calldata(self, expr: z3.ExprRef) -> bool:
        """Helper to check if expression only contains calldata-tainted variables."""
        # Get all variables in the expression
        # We can use the logic that any children must also be derived from calldata
        var_id = str(expr)
        if var_id in self._tainted:
            return self._tainted[var_id].source == "calldata"
            
        if hasattr(expr, "children"):
            children = expr.children()
            if not children: # leaf node not in _tainted (like a constant or other var)
                # If it's a constant, it's fine as part of a controllable expression (e.g. mask)
                return True if z3.is_const(expr) and not z3.is_app(expr) else False

            return all(self._is_derived_only_from_calldata(c) for c in children)
        
        return False

    def get_tainted_calldata_bytes(self, value: Union[z3.BitVecRef, int, bytes, None]) -> List[int]:
        """Returns a list of calldata offsets that contribute to this value."""
        if value is None or isinstance(value, (int, bytes)):
            return []
        
        offsets = []
        self._collect_offsets_recursive(value, offsets)
        return sorted(list(set(offsets)))

    def _collect_offsets_recursive(self, expr: z3.ExprRef, offsets: List[int]) -> None:
        var_id = str(expr)
        if var_id in self._tainted:
            info = self._tainted[var_id]
            if info.calldata_offset is not None:
                offsets.append(info.calldata_offset)
        
        if hasattr(expr, "children"):
            for child in expr.children():
                self._collect_offsets_recursive(child, offsets)

@dataclass
class CallTaintInfo:
    """Taint status of a CALL instruction's parameters."""
    target_tainted: bool = False
    selector_tainted: bool = False
    args_tainted: bool = False

@dataclass
class CallEncounter:
    """Records details of a CALL instruction encountered during symbolic execution."""
    pc: int
    gas: Union[z3.BitVecRef, int]
    target_address: Union[z3.BitVecRef, int]
    value: Union[z3.BitVecRef, int]
    args_offset: Union[z3.BitVecRef, int]
    args_size: Union[z3.BitVecRef, int]
    
    # Decoded fields (if possible)
    function_selector: Optional[Union[bytes, z3.BitVecRef]] = None
    arg1_recipient: Optional[Union[z3.BitVecRef, int]] = None
    arg2_amount: Optional[Union[z3.BitVecRef, int]] = None
    
    taint: CallTaintInfo = field(default_factory=CallTaintInfo)
    path_constraints: List[z3.BoolRef] = field(default_factory=list)
    seed_calldata: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        """Converts to a serializable dictionary."""
        return {
            "pc": self.pc,
            "target": str(self.target_address),
            "selector": self.function_selector.hex() if isinstance(self.function_selector, bytes) else str(self.function_selector),
            "recipient": str(self.arg1_recipient),
            "amount": str(self.arg2_amount),
            "target_tainted": self.taint.target_tainted,
            "args_tainted": self.taint.args_tainted,
        }

@dataclass
class SymbolicState:
    """Represents the complete state of the EVM at a specific point in execution."""
    pc: int
    stack: List[Union[z3.BitVecRef, int]] = field(default_factory=list)
    memory: Dict[Any, Union[z3.BitVecRef, int]] = field(default_factory=dict)
    storage: Dict[Any, Union[z3.BitVecRef, int]] = field(default_factory=dict)
    path_constraints: List[z3.BoolRef] = field(default_factory=list)
    taint_map: TaintMap = field(default_factory=TaintMap)
    call_depth: int = 0
    branch_table_visits: int = 0
    visit_counts: Dict[int, int] = field(default_factory=dict)
    
    # Transaction context
    calldata: z3.BitVecRef = field(default_factory=lambda: z3.BitVec("calldata", 2048 * 8))
    caller: Union[z3.BitVecRef, int] = field(default_factory=lambda: z3.BitVec("caller", 256))
    origin: Union[z3.BitVecRef, int] = field(default_factory=lambda: z3.BitVec("origin", 256))
    callvalue: Union[z3.BitVecRef, int] = field(default_factory=lambda: z3.BitVec("callvalue", 256))
    
    # Trace info
    calls_encountered: List[CallEncounter] = field(default_factory=list)

    def is_feasible(self) -> bool:
        """Checks if current path constraints are satisfiable."""
        solver = z3.Solver()
        solver.set("timeout", 5000) 
        solver.add(*self.path_constraints)
        return solver.check() == z3.sat

    def fork(self, condition: Optional[z3.BoolRef] = None) -> SymbolicState:
        """Creates a copy of the state, optionally adding a path constraint."""
        new_state = copy.deepcopy(self)
        if condition is not None:
            new_state.path_constraints.append(condition)
        return new_state

    def copy(self) -> SymbolicState:
        """Returns a deep copy of the state."""
        return copy.deepcopy(self)

# --- Pydantic Models for Engine I/O ---

class ExecutionTrace(BaseModel):
    """Summarizes a completed execution path."""
    path_constraints: List[str] 
    calls: List[Dict[str, Any]]
    final_pc: int
    is_terminal: bool
    taint_map: Optional[TaintMap] = None

    class Config:
        arbitrary_types_allowed = True
