# VALIDATION_ENGINE.md

## Responsibilities

Verifies that the generated exploits actually work in an accurate EVM environment. This engine simulates execution on a local fork with the precise historical state and verifies the existence of ERC-20 Transfer events. This is a ground truth check — no broadcast to a real network is performed.

---

## KEY SECURITY PRINCIPLE

> **The validation engine operates ONLY on a local fork. No transactions are ever broadcast to mainnet, testnet, or any other network. This is a defensive analysis tool, not an attack tool.**

---

## Input / Output

```python
@dataclass
class ValidationInput:
    exploits: list[Exploit]
    contract_address: str
    rpc_url: Optional[str]  # to load historical state
    config: ValidationConfig

@dataclass
class ValidationConfig:
    require_transfer_event: bool = True
    simulate_only: bool = True       # ALWAYS True, no broadcast
    state_cache_dir: Optional[str] = None  # cache state for speed

@dataclass
class ValidationOutput:
    validated_exploits: list[ValidatedExploit]
    success_count: int
    failure_count: int
    total_estimated_loss_usd: float
```

---

## Local EVM Fork Setup

```python
class LocalEVMFork:
    """
    Wrapper around py-evm to simulate execution
    on a specific historical state.
    """
    
    def __init__(self, rpc_url: str, block_number: int):
        self.rpc_url = rpc_url
        self.block_number = block_number
        self._chain = None
    
    def setup(self, contract_address: str) -> None:
        """
        Load state from an archive node:
        1. Block header (for timestamp, gas limit, etc.)
        2. Contract bytecode
        3. Contract storage (for state-dependent logic)
        4. Contract ETH balance
        5. Token balances (from token contracts)
        """
        from eth.chains.mainnet import MainnetChain
        from eth.db.atomic import AtomicDB
        
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        # Load block state
        block = w3.eth.get_block(self.block_number)
        
        # Build minimal state database
        db = AtomicDB()
        
        # Load contract code
        code = w3.eth.get_code(contract_address, block_identifier=self.block_number)
        
        # Load relevant storage slots
        # (this is complex: need to know which slots are important)
        # Simplified: load all slots accessed in traces
        
        self._chain = self._build_chain(db, block, contract_address, code)
    
    def execute_transaction(
        self,
        from_address: str,
        to_address: str,
        calldata: bytes,
        value: int,
        gas_limit: int,
    ) -> TransactionResult:
        """
        Execute a single transaction in the fork state.
        Returns result with executed PCs, logs, and return data.
        """
        ...
    
    def get_event_logs(self, result: TransactionResult, topic: str) -> list[dict]:
        """Extract event logs from the transaction result."""
        ...
```

---

## Exploit Validation Logic

```python
class ExploitValidator:
    
    # ERC-20 Transfer event signature
    TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    APPROVAL_EVENT_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    
    def __init__(self, rpc_url: Optional[str]):
        self.rpc_url = rpc_url
    
    def validate(self, exploit: Exploit) -> ValidatedExploit:
        """
        Validate an exploit by simulating it on a local fork.
        """
        try:
            fork = LocalEVMFork(
                rpc_url=self.rpc_url,
                block_number=exploit.block_number
            )
            fork.setup(exploit.to_address)
            
            result = fork.execute_transaction(
                from_address=exploit.from_address,
                to_address=exploit.to_address,
                calldata=exploit.calldata,
                value=exploit.value,
                gas_limit=exploit.gas_limit
            )
            
            # Check 1: Transaction success (status = 1, NOT REVERT)
            if not result.success:
                return ValidatedExploit(
                    exploit=exploit,
                    success=False,
                    validation_error=f"Transaction reverted: {result.revert_reason}"
                )
            
            # Check 2: Valid ERC-20 Transfer event from victim to adversary exist
            transfer_valid = self._verify_transfer_event(
                result=result,
                token_address=exploit.target_token,
                from_address=exploit.to_address,  # victim contract
                to_address=exploit.from_address,  # adversary
                expected_amount=exploit.expected_transfer_amount
            )
            
            if not transfer_valid:
                return ValidatedExploit(
                    exploit=exploit,
                    success=False,
                    validation_error="No valid Transfer event found in logs"
                )
            
            # Success!
            estimated_loss = self._estimate_loss(
                token_address=exploit.target_token,
                amount=exploit.expected_transfer_amount
            )
            
            return ValidatedExploit(
                exploit=exploit,
                success=True,
                tx_receipt=result.to_dict(),
                transfer_events=result.logs,
                estimated_loss_usd=estimated_loss,
                validation_error=None
            )
        
        except Exception as e:
            logger.error(f"Validation error for exploit at PC={exploit.vuln.call_pc}: {e}")
            return ValidatedExploit(
                exploit=exploit,
                success=False,
                validation_error=f"Validation exception: {str(e)}"
            )
    
    def _verify_transfer_event(
        self,
        result: TransactionResult,
        token_address: str,
        from_address: str,
        to_address: str,
        expected_amount: int
    ) -> bool:
        """
        Verify ERC-20 Transfer(from, to, value) event:
        - Log emitted by token_address
        - topics[0] == TRANSFER_EVENT_TOPIC
        - topics[1] (indexed from) == from_address
        - topics[2] (indexed to) == to_address
        - data == expected_amount (or at least > 0)
        """
        for log in result.logs:
            if (log['address'].lower() != token_address.lower()):
                continue
            
            if len(log['topics']) < 3:
                continue
            
            if log['topics'][0].hex() != self.TRANSFER_EVENT_TOPIC.lstrip("0x"):
                continue
            
            log_from = "0x" + log['topics'][1].hex()[-40:]
            log_to = "0x" + log['topics'][2].hex()[-40:]
            log_amount = int(log['data'].hex(), 16) if log['data'] else 0
            
            if (log_from.lower() == from_address.lower() and
                log_to.lower() == to_address.lower() and
                log_amount > 0):
                return True
        
        return False
```

---

## Fallback: Validation without Archive Node

If no archive node is available (offline mode):

```python
def validate_offline(self, exploit: Exploit, bytecode: bytes) -> ValidatedExploit:
    """
    Simplified validation: run in py-evm without full historical state.
    Load minimal state (only contract bytecode).
    Check if the CALL at vuln.call_pc is executed (not full success).
    """
    # Setup minimal EVM with only bytecode
    # No storage state, no token balances
    # Only check: is the CALL instruction reached?
    
    executed_pcs = self._run_minimal_evm(
        bytecode=bytecode,
        calldata=exploit.calldata,
        from_address=exploit.from_address
    )
    
    call_reached = exploit.vuln.call_pc in executed_pcs
    
    return ValidatedExploit(
        exploit=exploit,
        success=call_reached,  # partial validation
        validation_error=None if call_reached else "CALL PC not reached",
        is_partial_validation=True  # flag this as partial validation
    )
```

---

## Batch Validation

```python
def validate_batch(
    self, 
    exploits: list[Exploit],
    max_concurrent: int = 5
) -> list[ValidatedExploit]:
    """
    Validate multiple exploits in parallel.
    Use asyncio for concurrency, not threading (GIL friendly).
    """
    import asyncio
    
    async def validate_async(exploit: Exploit) -> ValidatedExploit:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.validate, exploit)
    
    async def run_all():
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_validate(exploit):
            async with semaphore:
                return await validate_async(exploit)
        
        return await asyncio.gather(*[bounded_validate(e) for e in exploits])
    
    return asyncio.run(run_all())
```

---

## TransactionResult Model

```python
@dataclass
class TransactionResult:
    success: bool          # True if status = 1 (STOP/RETURN), False if REVERT
    return_data: bytes
    gas_used: int
    logs: list[dict]       # event logs
    executed_pcs: set[int] # for preliminary validation
    revert_reason: Optional[str]
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "gas_used": self.gas_used,
            "logs_count": len(self.logs),
            "return_data": self.return_data.hex()
        }
```

---

## Test Cases

```python
def test_successful_exploit_validates():
    """
    A correct exploit generates a Transfer event.
    This test requires mocking LocalEVMFork or a known bytecode fixture.
    """
    ...

def test_reverted_tx_fails_validation():
    """
    A REVERTED transaction is not considered a valid exploit.
    """
    ...

def test_transfer_event_to_wrong_recipient_fails():
    """
    Transfer to an address other than the adversary is not considered valid.
    """
    ...

def test_zero_amount_transfer_fails():
    """
    Transfer amount of 0 is invalid (no assets stolen).
    """
    ...

def test_offline_validation_fallback():
    """
    Without an archive node, offline mode can still check CALL reachability.
    """
    ...
```
