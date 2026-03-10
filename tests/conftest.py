import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def bytecode_indirect_jump() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "indirect_jump.hex").read_text().strip()
    return bytes.fromhex(hex_str)

@pytest.fixture
def bytecode_vulnerable_transfer() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "vulnerable_transfer.hex").read_text().strip()
    return bytes.fromhex(hex_str)

@pytest.fixture
def bytecode_safe() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "safe_contract.hex").read_text().strip()
    return bytes.fromhex(hex_str)

@pytest.fixture
def bytecode_push_disguised() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "push_disguised.hex").read_text().strip()
    return bytes.fromhex(hex_str)
