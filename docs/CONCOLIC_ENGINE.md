# CONCOLIC_ENGINE.md

## Responsibilities

Combines concrete execution (using historical transactions as seeds) with symbolic analysis to find vulnerabilities efficiently. This is Little Bodi's primary mode — faster and more accurate than pure symbolic execution because constraint solving is significantly simpler when starting from a concrete trace.

---

## Motivation

From the paper: 54% of vulnerable contracts found by concolic mode timed out in pure symbolic mode. Reason: constraint solving from scratch is much harder. With concrete seeds, we already know which parts of the path are feasible.

---

## Input / Output

```python
@dataclass
class ConcolicInput:
    deobfuscated_bytecode: bytes
    deobfuscated_cfg: ControlFlowGraph
    contract_address: str
    rpc_url: Optional[str]
    config: ConcolicConfig

@dataclass
class ConcolicConfig:
    max_seeds: int = 50
    timeout_per_seed: int = 120
    fallback_to_symbolic: bool = True
    symbolic_config: SymbolicConfig = field(default_factory=SymbolicConfig)

@dataclass
class ConcolicOutput:
    execution_traces: list[ExecutionTrace]
    seeds_used: int
    seeds_skipped: int
    fell_back_to_symbolic: bool
    vulnerability_hints: list[CallEncounter]  # CALLs found via concolic
```

---

## Seed Extraction

### What is a Seed Input?

A seed is a tuple `(origin, caller, calldata, value, block_number)` from a historical transaction that:
1. Executed successfully (status = 1)
2. Produced an ERC-20 transfer involving the contract as the sender

This ensures the seed represents an execution path relevant to asset management.

### Seed Extraction Algorithm

```python
class SeedExtractor:
    def __init__(self, rpc_url: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
    
    async def extract_seeds(
        self, 
        contract_address: str, 
        max_seeds: int = 50
    ) -> list[SeedInput]:
        """
        1. Fetch recent transactions to contract_address
        2. Filter for successful txs + ERC-20 events from contract
        3. Extract input parameters
        """
        seeds = []
        
        # Fetch transactions via eth_getLogs or Etherscan API
        txs = await self._fetch_transactions(contract_address)
        
        for tx in txs:
            if tx.status != 1:  # failed tx
                continue
            
            # Check ERC-20 Transfer event where contract is 'from'
            erc20_transfers = await self._get_erc20_transfers_from(
                tx_hash=tx.hash,
                from_address=contract_address,
                block_number=tx.block_number
            )
            
            if not erc20_transfers:
                continue
            
            # Extract call from tx trace directly to contract
            direct_calls = [
                call for call in tx.trace
                if call.to == contract_address and call.calldata != b''
            ]
            
            for call in direct_calls:
                seeds.append(SeedInput(
                    origin=tx.from_address,    # tx.origin
                    caller=call.from_address,  # msg.sender
                    calldata=call.calldata,
                    value=call.value,
                    block_number=tx.block_number
                ))
                
                if len(seeds) >= max_seeds:
                    return seeds
        
        return seeds
    
    async def _get_erc20_transfers_from(
        self, 
        tx_hash: str, 
        from_address: str,
        block_number: int
    ) -> list[ERC20Transfer]:
        """
        Check Transfer event log: keccak256("Transfer(address,address,uint256)")
        = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
        
        Filter: topics[1] (from) == from_address
        """
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        
        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        transfers = []
        
        for log in receipt.logs:
            if (len(log.topics) >= 3 and 
                log.topics[0].hex() == TRANSFER_TOPIC and
                "0x" + log.topics[1].hex()[-40:].lower() == from_address.lower()):
                
                transfers.append(ERC20Transfer(
                    token_address=log.address,
                    from_addr=from_address,
                    to_addr="0x" + log.topics[2].hex()[-40:],
                    amount=int(log.data.hex(), 16)
                ))
        
        return transfers
```

---

## Concolic Execution Algorithm

```python
class ConcolicEngine:
    """
    Hybrid execution: use concrete trace as a guide,
    while tracking symbolic expressions for parameter analysis.
    """
    
    def run_with_seed(
        self, 
        seed: SeedInput,
        bytecode: bytes,
        cfg: ControlFlowGraph,
    ) -> Optional[ExecutionTrace]:
        """
        Execute with concrete values from seed, while tracking
        symbolic expressions for taint analysis.
        """
        # Initialize state with CONCRETE values from seed
        state = ConcreteSymbolicState(
            pc=0,
            calldata_concrete=seed.calldata,
            calldata_symbolic=z3.BitVec("calldata", len(seed.calldata) * 8),
            caller_concrete=int(seed.caller, 16),
            origin_concrete=int(seed.origin, 16),
            value_concrete=seed.value,
            block_number=seed.block_number
        )
        
        # Initialize taint: all calldata bytes are tainted
        for i in range(len(seed.calldata)):
            state.taint_map.mark_byte_tainted(i)
        
        calls_found = []
        
        while state.pc < len(bytecode):
            instr = fetch_instruction(bytecode, state.pc)
            
            # Execute CONCRETELY (follow concrete values from seed)
            # But ALSO track symbolic expressions in parallel
            
            match instr.opcode:
                case 0x35:  # CALLDATALOAD
                    offset = state.concrete_stack_top()
                    concrete_val = int.from_bytes(
                        seed.calldata[offset:offset+32].ljust(32, b'\x00'), 'big'
                    )
                    symbolic_val = z3.Extract(
                        (offset + 32) * 8 - 1, offset * 8,
                        state.calldata_symbolic
                    )
                    state.push_both(concrete_val, symbolic_val)
                    state.mark_stack_top_tainted(offset=offset)
                
                case 0x57:  # JUMPI
                    dest_concrete = state.concrete_stack_pop()
                    cond_concrete = state.concrete_stack_pop()
                    dest_symbolic = state.symbolic_stack_pop()
                    cond_symbolic = state.symbolic_stack_pop()
                    
                    # Follow CONCRETE path (no forking)
                    if cond_concrete != 0:
                        state.pc = dest_concrete
                        state.path_constraints.append(cond_symbolic != 0)
                    else:
                        state.pc = instr.pc + 1
                        state.path_constraints.append(cond_symbolic == 0)
                
                case 0xF1:  # CALL
                    call = state.extract_call_encounter(instr.pc)
                    calls_found.append(call)
                    
                    # Simulate call return (concrete: assume success = 1)
                    state.push_concrete(1)
                    state.push_symbolic(z3.BitVecVal(1, 256))
                
                case _:
                    execute_standard_op(instr, state)
        
        return ExecutionTrace(
            seed=seed,
            calls=calls_found,
            path_constraints=state.path_constraints,
            taint_map=state.taint_map
        )
    
    def run(self, inp: ConcolicInput) -> ConcolicOutput:
        seeds = self._extract_or_load_seeds(inp)
        
        if not seeds and inp.config.fallback_to_symbolic:
            logger.info("No seeds found, falling back to symbolic execution")
            symbolic_result = SymbolicExecutionEngine().run(
                SymbolicExecutionInput(
                    deobfuscated_cfg=inp.deobfuscated_cfg,
                    deobfuscated_bytecode=inp.deobfuscated_bytecode,
                    config=inp.config.symbolic_config
                )
            )
            return ConcolicOutput(
                execution_traces=symbolic_result.execution_traces,
                seeds_used=0,
                fell_back_to_symbolic=True,
                ...
            )
        
        all_traces = []
        for seed in seeds:
            try:
                trace = self.run_with_seed(
                    seed=seed,
                    bytecode=inp.deobfuscated_bytecode,
                    cfg=inp.deobfuscated_cfg
                )
                if trace:
                    all_traces.append(trace)
            except TimeoutError:
                logger.warning(f"Seed timeout at block {seed.block_number}")
        
        return ConcolicOutput(
            execution_traces=all_traces,
            seeds_used=len(seeds),
            fell_back_to_symbolic=False,
            ...
        )
```

---

## Concolic State (Dual-Track)

```python
@dataclass
class ConcreteSymbolicState:
    """
    Track two values in parallel:
    - Concrete: actual value (from seed)
    - Symbolic: Z3 expression (for constraint solving)
    """
    
    # Stacks (concrete and symbolic tracks respectively)
    _concrete_stack: list[int]
    _symbolic_stack: list[z3.BitVecRef]
    
    def push_both(self, concrete: int, symbolic: z3.BitVecRef):
        self._concrete_stack.append(concrete)
        self._symbolic_stack.append(symbolic)
    
    def pop_both(self) -> tuple[int, z3.BitVecRef]:
        return self._concrete_stack.pop(), self._symbolic_stack.pop()
    
    def push_concrete_only(self, value: int):
        """For values unrelated to calldata."""
        self._concrete_stack.append(value)
        self._symbolic_stack.append(z3.BitVecVal(value, 256))
```

---

## Advantages vs Pure Symbolic

| Aspect | Pure Symbolic | Concolic |
|---|---|---|
| Path exploration | Forks at every JUMPI → exponential | Follows concrete trace → linear |
| Constraint complexity | Fully symbolic → slow solver | Partially concrete → fast solver |
| Coverage | Theoretically complete | Limited to seed paths |
| Timeout rate | 54% timeout (from paper) | Significantly lower |
| False positive | Higher | Lower (concrete evidence) |

---

## Test Cases

```python
def test_seed_extraction_filters_correct_txs():
    """
    Only successful transactions with ERC-20 transfer FROM contract
    should be accepted as seeds.
    """
    ...

def test_concrete_path_followed_correctly():
    """
    Concolic execution must follow the same path as the concrete tx.
    """
    ...

def test_symbolic_track_taint_propagation():
    """
    Even with concrete execution, taint tracking continues on the symbolic track.
    """
    ...

def test_fallback_to_symbolic_when_no_seeds():
    """
    If seeds are empty and fallback=True, symbolic mode is executed.
    """
    ...
```
