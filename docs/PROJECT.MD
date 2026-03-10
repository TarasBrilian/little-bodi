# Little Bodi — EVM Smart Contract Vulnerability Analysis Engine

## Background & Motivation

The paper "Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts" (Yang et al., 2025) demonstrates that bytecode obfuscation in EVM smart contracts not only fails to protect assets but actively hides security flaws from existing analysis tools. Among 6,554 MEV bots studied, 1,030 were proven vulnerable with potential losses of $10.6 million — and the majority of existing tools could not detect them due to an inability to handle control flow obfuscation.

**Little Bodi** is a Python implementation of the SKANF concept designed as a modular, reproducible EVM bytecode analysis pipeline that can be used defensively by developers and researchers.

---

## Problems Solved

### 1. Control Flow Obfuscation
Closed-source smart contracts often use indirect jumps (jump targets determined at runtime) to hide internal logic. Existing tools like Gigahorse, Mythril, ETHBMC, and JACKAL fail to build an accurate CFG, leaving large portions of the bytecode unanalyzable.

### 2. Inadequate Vulnerability Detection
- Simple pattern matching misses vulnerabilities where only partial parameters are attacker-controlled.
- Pure symbolic execution suffers from path explosion in complex contracts (MEV bots, DEX trading, flash loans).
- Timeouts are common even without obfuscation.

### 3. Asset Management Vulnerability
Flaws that allow an attacker to transfer ERC-20 tokens from the contract account to their own, including via `tx.origin` phishing and callback manipulation (MEV phishing attacks).

---

## Implemented Solution

| Component | Solution |
|---|---|
| Deobfuscation | Branch table reconstruction from all valid JUMPDESTs |
| Vulnerability Detection | Symbolic + taint analysis on CALL parameters |
| Efficiency | Concolic execution with seeds from historical transactions |
| Exploit Generation | Constraint solving to generate exploit calldata |
| Validation | Local simulation on historical fork state |

---

## Project Scope

- **Target**: EVM bytecode (Ethereum-compatible chains)
- **Language**: Python 3.12+
- **Vulnerability Focus**: Asset management vulnerabilities (ERC-20 theft via unprotected CALL)
- **Input**: Contract bytecode + optional historical transactions (JSON/RPC)
- **Output**: Vulnerability report + exploit transaction (if successful)

---

## Directory Structure

```
little_bodi/
├── core/
│   ├── bytecode_analysis/      # Disassembly, CFG construction
│   ├── deobfuscation/          # Indirect jump resolution, branch table
│   ├── symbolic_execution/     # Path exploration with symbolic vars
│   ├── concolic_execution/     # Hybrid execution with concrete seeds
│   ├── vulnerability/          # Taint analysis, oracle detection
│   ├── exploit_generation/     # Calldata synthesis
│   └── validation/             # Local fork simulation
├── engines/                    # Engine interfaces (see architecture.md)
├── reporting/                  # Output formatter & report generator
├── data/
│   ├── seeds/                  # Historical transaction cache
│   └── results/                # Vulnerability reports, exploits
├── tests/
├── scripts/
│   ├── analyze.py              # CLI entrypoint
│   └── batch_analyze.py        # Batch MEV bot analysis
├── configs/
│   └── settings.yaml
├── requirements.txt
└── README.md
```

---

## Tech Stack

| Requirement | Library |
|---|---|
| EVM execution | `py-evm` (eth) |
| Bytecode disassembly | `pyevmasm` / custom disassembler |
| Constraint solving | `z3-solver` |
| RPC/archive node | `web3.py` |
| Taint tracking | custom implementation |
| CFG construction | custom graph (networkx) |
| Testing | `pytest` |
| CLI | `click` |
| Async I/O | `asyncio` + `aiohttp` |

---

## Pipeline Workflow (High-Level)

```
[Bytecode Input]
      │
      ▼
[Stage A] Bytecode Analysis & Deobfuscation
  → Disassemble bytecode
  → Build CFG
  → Identify indirect jumps
  → Insert branch table → deobfuscated bytecode
      │
      ▼
[Stage B] Vulnerability Detection
  → Extract seed inputs from historical tx (if available)
  → Concolic execution (or symbolic fallback)
  → Taint propagation: calldata → CALL parameters
  → Classify: adversary-controllable vs risky-but-fixed
      │
      ▼
[Stage C] Exploit Generation & Validation
  → Synthesize calldata via constraint solving
  → Validate on local fork (py-evm)
  → Verify ERC-20 Transfer/Approval event logs
      │
      ▼
[Report Output]
  → JSON vulnerability report
  → Exploit transaction object
  → Markdown summary
```

---

## Target Metrics

| Metric | Target |
|---|---|
| Code coverage after deobfuscation | >90% for contracts with initial coverage <50% |
| Analysis per contract | <100 seconds (concolic mode) |
| False positive rate | Minimal (only flags that can be validated) |
| Token support | WETH, WBTC, USDC, USDT, DAI, UNI, LINK (extendable) |

---

## Key References

- Yang et al., "Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts", arXiv:2504.13398v3, 2025
- Greed symbolic execution engine (concolic execution concept basis)
- Gigahorse decompiler (CFG lifting concept basis)
- EVM Yellow Paper (Gavin Wood, 2014)