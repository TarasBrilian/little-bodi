# core/constants.py
# Single source of truth for all EVM and project-specific constants.
# DO NOT hardcode these values elsewhere — always import from here.

from __future__ import annotations

# ---------------------------------------------------------------------------
# Tool Metadata
# ---------------------------------------------------------------------------

TOOL_VERSION: str = "0.1.0"

# ---------------------------------------------------------------------------
# EVM Fundamentals
# ---------------------------------------------------------------------------

EVM_WORD_BITS: int = 256
EVM_WORD_BYTES: int = 32
EVM_ADDRESS_BYTES: int = 20
MAX_BYTECODE_SIZE: int = 24_576       # EIP-170: 24KB hard limit (deployment)
MAX_BYTECODE_ANALYSIS: int = 65_536   # Relaxed limit for analysis (non-deployment)

# ---------------------------------------------------------------------------
# Opcode Values
# ---------------------------------------------------------------------------

# Arithmetic
OP_STOP         = 0x00
OP_ADD          = 0x01
OP_MUL          = 0x02
OP_SUB          = 0x03
OP_DIV          = 0x04
OP_SDIV         = 0x05
OP_MOD          = 0x06
OP_SMOD         = 0x07
OP_ADDMOD       = 0x08
OP_MULMOD       = 0x09
OP_EXP          = 0x0A
OP_SIGNEXTEND   = 0x0B

# Comparison
OP_LT           = 0x10
OP_GT           = 0x11
OP_SLT          = 0x12
OP_SGT          = 0x13
OP_EQ           = 0x14
OP_ISZERO       = 0x15

# Bitwise
OP_AND          = 0x16
OP_OR           = 0x17
OP_XOR          = 0x18
OP_NOT          = 0x19
OP_BYTE         = 0x1A
OP_SHL          = 0x1B
OP_SHR          = 0x1C
OP_SAR          = 0x1D

# Hash
OP_KECCAK256    = 0x20

# Environment
OP_ADDRESS      = 0x30
OP_BALANCE      = 0x31
OP_ORIGIN       = 0x32   # tx.origin
OP_CALLER       = 0x33   # msg.sender
OP_CALLVALUE    = 0x34
OP_CALLDATALOAD = 0x35
OP_CALLDATASIZE = 0x36
OP_CALLDATACOPY = 0x37
OP_CODESIZE     = 0x38
OP_CODECOPY     = 0x39
OP_GASPRICE     = 0x3A
OP_EXTCODESIZE  = 0x3B
OP_EXTCODECOPY  = 0x3C
OP_RETURNDATASIZE = 0x3D
OP_RETURNDATACOPY = 0x3E
OP_EXTCODEHASH  = 0x3F
OP_BLOCKHASH    = 0x40
OP_COINBASE     = 0x41
OP_TIMESTAMP    = 0x42
OP_NUMBER       = 0x43
OP_PREVRANDAO   = 0x44
OP_GASLIMIT     = 0x45
OP_CHAINID      = 0x46
OP_SELFBALANCE  = 0x47
OP_BASEFEE      = 0x48

# Memory / Storage
OP_POP          = 0x50
OP_MLOAD        = 0x51
OP_MSTORE       = 0x52
OP_MSTORE8      = 0x53
OP_SLOAD        = 0x54
OP_SSTORE       = 0x55
OP_PC           = 0x58
OP_MSIZE        = 0x59
OP_GAS          = 0x5A

# Control Flow
OP_JUMP         = 0x56
OP_JUMPI        = 0x57
OP_JUMPDEST     = 0x5B

# Push (PUSH1=0x60 ... PUSH32=0x7F)
OP_PUSH1        = 0x60
OP_PUSH2        = 0x61
OP_PUSH32       = 0x7F

# Dup (DUP1=0x80 ... DUP16=0x8F)
OP_DUP1         = 0x80
OP_DUP16        = 0x8F

# Swap (SWAP1=0x90 ... SWAP16=0x9F)
OP_SWAP1        = 0x90
OP_SWAP16       = 0x9F

# Logging
OP_LOG0         = 0xA0
OP_LOG4         = 0xA4

# System
OP_CREATE       = 0xF0
OP_CALL         = 0xF1
OP_CALLCODE     = 0xF2
OP_RETURN       = 0xF3
OP_DELEGATECALL = 0xF4
OP_CREATE2      = 0xF5
OP_STATICCALL   = 0xFA
OP_REVERT       = 0xFD
OP_INVALID      = 0xFE
OP_SELFDESTRUCT = 0xFF

# ---------------------------------------------------------------------------
# Opcode Lookup Table (int -> mnemonic string)
# ---------------------------------------------------------------------------

OPCODE_TABLE: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB",
    0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
    0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT",
    0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
    0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
    0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
    0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}

# PUSH1-PUSH32
for _i in range(1, 33):
    OPCODE_TABLE[0x5F + _i] = f"PUSH{_i}"

# DUP1-DUP16
for _i in range(1, 17):
    OPCODE_TABLE[0x7F + _i] = f"DUP{_i}"

# SWAP1-SWAP16
for _i in range(1, 17):
    OPCODE_TABLE[0x8F + _i] = f"SWAP{_i}"

# LOG0-LOG4
for _i in range(5):
    OPCODE_TABLE[0xA0 + _i] = f"LOG{_i}"

# ---------------------------------------------------------------------------
# Opcode properties
# ---------------------------------------------------------------------------

# Opcodes that terminate a basic block (terminators)
BLOCK_TERMINATORS: frozenset[int] = frozenset({
    OP_STOP, OP_JUMP, OP_JUMPI, OP_RETURN,
    OP_REVERT, OP_INVALID, OP_SELFDESTRUCT
})

# Opcodes that open a new basic block afterwards (non-terminator but split)
BLOCK_STARTERS: frozenset[int] = frozenset({OP_JUMPDEST})

# Opcodes that are CALL instructions (execution sinks)
CALL_OPCODES: frozenset[int] = frozenset({
    OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL
})

# Opcodes that are taint sources (from calldata)
TAINT_SOURCES: frozenset[int] = frozenset({
    OP_CALLDATALOAD, OP_CALLDATACOPY
})

# Opcodes yang propagate taint (conservative: jika ada input tainted → output tainted)
TAINT_PROPAGATORS: frozenset[int] = frozenset({
    OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_SDIV, OP_MOD, OP_SMOD,
    OP_ADDMOD, OP_MULMOD, OP_EXP, OP_SIGNEXTEND,
    OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_ISZERO,
    OP_AND, OP_OR, OP_XOR, OP_NOT,
    OP_BYTE, OP_SHL, OP_SHR, OP_SAR,
    OP_MLOAD, OP_MSTORE, OP_MSTORE8,
    OP_SLOAD,
    # DUP1-DUP16
    *range(OP_DUP1, OP_DUP16 + 1),
    # SWAP1-SWAP16
    *range(OP_SWAP1, OP_SWAP16 + 1),
})

# ---------------------------------------------------------------------------
# Deobfuscation offsets (sesuai paper SKANF)
# ---------------------------------------------------------------------------

BRANCH_TABLE_OFFSET: int = 0xE000  # lokasi branch table di bytecode
INTERMEDIATE_OFFSET: int = 0xF000  # lokasi intermediate gadgets

# Pruning rule: max kunjungan ke branch table per execution path
BRANCH_TABLE_MAX_VISITS: int = 2

# ---------------------------------------------------------------------------
# ERC-20 Function Selectors
# keccak256("functionName(types)")[0:4]
# ---------------------------------------------------------------------------

ERC20_SELECTOR_TRANSFER      = bytes.fromhex("a9059cbb")  # transfer(address,uint256)
ERC20_SELECTOR_TRANSFER_FROM = bytes.fromhex("23b872dd")  # transferFrom(address,address,uint256)
ERC20_SELECTOR_APPROVE       = bytes.fromhex("095ea7b3")  # approve(address,uint256)
ERC20_SELECTOR_BALANCE_OF    = bytes.fromhex("70a08231")  # balanceOf(address)
ERC20_SELECTOR_ALLOWANCE     = bytes.fromhex("dd62ed3e")  # allowance(address,address)

RISKY_ERC20_SELECTORS: frozenset[bytes] = frozenset({
    ERC20_SELECTOR_TRANSFER,
    ERC20_SELECTOR_TRANSFER_FROM,
    ERC20_SELECTOR_APPROVE,
})

# ---------------------------------------------------------------------------
# ERC-20 Event Topics
# keccak256("EventName(types)")
# ---------------------------------------------------------------------------

ERC20_TOPIC_TRANSFER = bytes.fromhex(
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
ERC20_TOPIC_APPROVAL = bytes.fromhex(
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)

# ---------------------------------------------------------------------------
# Known ERC-20 Token Addresses (Ethereum Mainnet, checksum)
# ---------------------------------------------------------------------------

TRACKED_TOKENS: dict[str, str] = {
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "WETH",
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": "WBTC",
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": "USDC",
    "0xdAC17F958D2ee523a2206206994597C13D831ec7": "USDT",
    "0x6B175474E89094C44Da98b954EedeAC495271d0F": "DAI",
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984": "UNI",
    "0x514910771AF9Ca656af840dff83E8264EcF986CA": "LINK",
}

TOKEN_DECIMALS: dict[str, int] = {
    "WETH": 18, "WBTC": 8, "USDC": 6, "USDT": 6,
    "DAI": 18, "UNI": 18, "LINK": 18,
}

# ---------------------------------------------------------------------------
# Adversary / Simulation Addresses
# ---------------------------------------------------------------------------

ADVERSARY_ADDRESS: str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ADVERSARY_ADDRESS_INT: int = int(ADVERSARY_ADDRESS, 16)

# ---------------------------------------------------------------------------
# Analysis Limits (defaults — can be overridden via config)
# ---------------------------------------------------------------------------

DEFAULT_MAX_SYMBOLIC_PATHS: int    = 10_000
DEFAULT_MAX_PATH_DEPTH: int        = 500
DEFAULT_TIMEOUT_SECONDS: int       = 600
DEFAULT_MAX_SEEDS: int             = 50
DEFAULT_MAX_TOKENS_PER_CONTRACT: int = 7
DEFAULT_GAS_LIMIT: int             = 1_000_000
DEFAULT_GAS_PRICE_GWEI: int        = 20

# ---------------------------------------------------------------------------
# Calldata Layout (ABI standard)
# ---------------------------------------------------------------------------

SELECTOR_OFFSET: int  = 0   # bytes 0-3
SELECTOR_SIZE: int    = 4
ARG1_OFFSET: int      = 4   # bytes 4-35
ARG1_SIZE: int        = 32
ARG2_OFFSET: int      = 36  # bytes 36-67
ARG2_SIZE: int        = 32

# ---------------------------------------------------------------------------
# Chain IDs
# ---------------------------------------------------------------------------

CHAIN_MAINNET:  int = 1
CHAIN_SEPOLIA:  int = 11155111
CHAIN_HOLESKY:  int = 17000
