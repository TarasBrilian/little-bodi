# core/concolic_execution/state.py
from __future__ import annotations
import z3
import copy
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union, Tuple, Any
from core.symbolic_execution.state import SymbolicState, TaintMap, CallEncounter

@dataclass
class ConcolicState(SymbolicState):
    """
    State for concolic execution that tracks both concrete and symbolic values.
    """
    concrete_stack: List[int] = field(default_factory=list)
    # The 'stack' from SymbolicState will be treated as the symbolic track.
    
    concrete_memory: Dict[int, int] = field(default_factory=dict)
    concrete_storage: Dict[int, int] = field(default_factory=dict)

    def push_both(self, concrete: int, symbolic: Union[z3.BitVecRef, int]):
        self.concrete_stack.append(concrete)
        self.stack.append(symbolic)

    def pop_both(self) -> Tuple[int, Union[z3.BitVecRef, int]]:
        if not self.concrete_stack or not self.stack:
            raise IndexError("Pop from empty concolic stack")
        return self.concrete_stack.pop(), self.stack.pop()

    def push_concrete_only(self, val: int):
        """Used for values that are purely concrete (not derived from symbolic input)."""
        self.concrete_stack.append(val)
        self.stack.append(val) # On symbolic track, it's just a constant

    def copy(self) -> ConcolicState:
        return copy.deepcopy(self)
