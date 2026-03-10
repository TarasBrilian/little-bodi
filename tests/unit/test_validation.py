# tests/unit/test_validation.py
"""
Unit tests for ValidationEngine.
All tests operate in local simulation mode — no live network calls.
"""
import pytest
from unittest.mock import MagicMock, patch
from typing import Optional

from core.validation.engine import ExploitValidator, ValidationEngine
from core.validation.models import TransactionResult, ValidatedExploit
from core.validation.local_fork import LocalEVMFork
from core.exploit_generation.models import Exploit
from core.pipeline import AnalysisContext, AnalysisConfig
from core.constants import ERC20_TOPIC_TRANSFER, ADVERSARY_ADDRESS

ADVERSARY = ADVERSARY_ADDRESS
VICTIM = "0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


def _make_exploit(
    transfer_amount: int = 10 ** 18,
    from_address: str = ADVERSARY,
    to_address: str = VICTIM,
    target_token: str = WETH,
) -> Exploit:
    return Exploit(
        vuln_call_pc=0x100,
        from_address=from_address,
        to_address=to_address,
        calldata=b"\xa9\x05\x9c\xbb" + b"\x00" * 12 + bytes.fromhex(ADVERSARY[2:]) + (transfer_amount).to_bytes(32, "big"),
        value=0,
        gas_limit=1_000_000,
        target_token=target_token,
        target_token_symbol="WETH",
        expected_transfer_amount=transfer_amount,
        estimated_loss_usd=3000.0,
    )


def _make_result(
    success: bool = True,
    logs: list = None,
    executed_pcs: set = None,
    revert_reason: Optional[str] = None,
) -> TransactionResult:
    return TransactionResult(
        success=success,
        logs=logs or [],
        executed_pcs=executed_pcs or set(),
        revert_reason=revert_reason,
    )


def _transfer_log(from_addr: str, to_addr: str, amount: int, token: str = WETH) -> dict:
    """Build a synthetic Transfer event log."""
    from_bytes = bytes.fromhex("000000000000000000000000" + from_addr[2:].lower().zfill(40))
    to_bytes = bytes.fromhex("000000000000000000000000" + to_addr[2:].lower().zfill(40))
    return {
        "address": token.lower(),
        "topics": [
            ERC20_TOPIC_TRANSFER,
            from_bytes,
            to_bytes,
        ],
        "data": amount.to_bytes(32, "big"),
    }


# ---------------------------------------------------------------------------
# ExploitValidator — unit tests
# ---------------------------------------------------------------------------

def test_successful_exploit_validates():
    """A correct exploit with a valid Transfer event is marked successful."""
    validator = ExploitValidator()
    exploit = _make_exploit()

    good_log = _transfer_log(
        from_addr=VICTIM,
        to_addr=ADVERSARY,
        amount=10 ** 18,
    )
    result = _make_result(success=True, logs=[good_log])

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            validated = validator.validate(exploit)

    assert validated.success is True
    assert validated.validation_error is None


def test_reverted_tx_fails_validation():
    """A reverted transaction is not a valid exploit."""
    validator = ExploitValidator()
    exploit = _make_exploit()
    result = _make_result(success=False, revert_reason="Ownable: caller is not owner")

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            validated = validator.validate(exploit)

    assert validated.success is False
    assert "reverted" in validated.validation_error.lower()


def test_transfer_event_to_wrong_recipient_fails():
    """Transfer to an address other than the adversary is not accepted."""
    validator = ExploitValidator()
    exploit = _make_exploit()

    wrong_log = _transfer_log(
        from_addr=VICTIM,
        to_addr="0x1234567890123456789012345678901234567890",  # wrong recipient
        amount=10 ** 18,
    )
    result = _make_result(success=True, logs=[wrong_log])

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            validated = validator.validate(exploit)

    assert validated.success is False
    assert "No valid Transfer event" in validated.validation_error


def test_zero_amount_transfer_fails():
    """A Transfer event with amount=0 is not accepted."""
    validator = ExploitValidator()
    exploit = _make_exploit(transfer_amount=0)

    zero_log = _transfer_log(from_addr=VICTIM, to_addr=ADVERSARY, amount=0)
    result = _make_result(success=True, logs=[zero_log])

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            validated = validator.validate(exploit)

    assert validated.success is False


def test_offline_validation_fallback():
    """
    Without an archive node, offline mode checks CALL reachability.
    Bytecode with only STOP has no CALL, so the vulnerable PC must not be reached.
    """
    validator = ExploitValidator()
    exploit = _make_exploit()
    exploit.vuln_call_pc = 0xFF  # Far beyond the 1-byte bytecode — impossible to reach

    # Bytecode: just a STOP
    bytecode = bytes([0x00])  # STOP at PC 0
    validated = validator.validate_offline(exploit, bytecode=bytecode)

    assert validated.is_partial_validation is True
    # CALL at PC 0xFF is not inside this 1-byte bytecode
    assert validated.success is False
    assert "CALL PC not reached" in validated.validation_error


def test_offline_partial_call_reached():
    """Offline mode returns success=True when the CALL PC is executed."""
    validator = ExploitValidator()
    exploit = _make_exploit()
    exploit.vuln_call_pc = 2  # OP_CALL will be at PC=2

    # Minimal bytecode: PUSH1 0x01, CALL-like — use STOP at PC 2 so executor marks PC 2 as executed
    # Actually easier: PUSH1 (2 bytes), then STOP so PC 2 is NOT executed normally.
    # Simpler: override execute_transaction to inject PC 2 into executed_pcs.
    result = _make_result(
        success=True,
        executed_pcs={0, 1, 2},  # PC 2 is reached
    )
    bytecode = bytes([0x60, 0x01, 0x00])  # PUSH1 1, STOP

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            validated = validator.validate_offline(exploit, bytecode=bytecode)

    assert validated.is_partial_validation is True
    assert validated.success is True  # PC 2 was in executed_pcs


# ---------------------------------------------------------------------------
# ValidationEngine integration test
# ---------------------------------------------------------------------------

def test_engine_integration():
    """ValidationEngine processes exploits and writes to ctx.validated_exploits."""
    config = AnalysisConfig()
    engine = ValidationEngine(config)

    exploit = _make_exploit()
    good_log = _transfer_log(from_addr=VICTIM, to_addr=ADVERSARY, amount=10 ** 18)
    result = _make_result(success=True, logs=[good_log])

    ctx = AnalysisContext(
        bytecode=b"\x00",
        contract_address=VICTIM,
        chain_id=1,
        block_number=None,
        config=config,
    )
    ctx.exploits = [exploit]

    with patch.object(LocalEVMFork, "execute_transaction", return_value=result):
        with patch.object(LocalEVMFork, "setup", return_value=None):
            ctx = engine.execute(ctx)

    assert len(ctx.validated_exploits) == 1
    assert ctx.validated_exploits[0].success is True
