# core/validation/models.py
"""Data models for the ValidationEngine."""
from __future__ import annotations
from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel, Field

from core.exploit_generation.models import Exploit


class ValidationConfig(BaseModel):
    """Configuration for the ValidationEngine."""
    require_transfer_event: bool = True
    simulate_only: bool = True       # ALWAYS True — no broadcast ever
    state_cache_dir: Optional[str] = None


class TransactionResult(BaseModel):
    """The outcome of executing an exploit transaction in a local fork."""
    success: bool
    return_data: bytes = b""
    gas_used: int = 0
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    executed_pcs: Set[int] = Field(default_factory=set)
    revert_reason: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable summary."""
        return {
            "success": self.success,
            "gas_used": self.gas_used,
            "logs_count": len(self.logs),
            "return_data": self.return_data.hex(),
        }


class ValidatedExploit(BaseModel):
    """A validated (or refuted) exploit with its simulation outcome."""
    exploit: Exploit
    success: bool
    tx_receipt: Optional[Dict[str, Any]] = None
    transfer_events: List[Dict[str, Any]] = Field(default_factory=list)
    estimated_loss_usd: float = 0.0
    validation_error: Optional[str] = None
    validation_note: Optional[str] = None
    is_partial_validation: bool = False

    class Config:
        arbitrary_types_allowed = True


class ValidationOutput(BaseModel):
    """Aggregate output of the ValidationEngine over all exploits."""
    validated_exploits: List[ValidatedExploit] = Field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    total_estimated_loss_usd: float = 0.0
