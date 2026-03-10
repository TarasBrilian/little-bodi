# core/concolic_execution/seed_extractor.py
from __future__ import annotations
import logging
from typing import List, Optional
from web3 import Web3
from core.concolic_execution.models import SeedInput
from core.constants import ERC20_TOPIC_TRANSFER

logger = logging.getLogger(__name__)

class SeedExtractor:
    """
    Extracts transaction seeds from historical blockchain data.
    Filters for successful transactions that triggered ERC-20 transfers from the contract.
    """
    def __init__(self, rpc_url: Optional[str]):
        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url)) if rpc_url else None

    def extract_seeds(
        self, 
        contract_address: str, 
        max_seeds: int = 50
    ) -> List[SeedInput]:
        """
        Fetches recent transactions and extracts seeds.
        Currently implements a simplified version that would ideally use Etherscan or eth_getLogs.
        """
        if not self.w3:
            logger.warning("No RPC URL provided, cannot extract seeds.")
            return []

        seeds: List[SeedInput] = []
        
        # In a real implementation, we would:
        # 1. Get transaction hashes involving contract_address (e.g. from Etherscan or logs)
        # 2. Filter for success and ERC-20 events
        # 3. Extract calldata and context
        
        # For now, we'll provide a hook for manual seed injection or basic log filtering if implemented.
        logger.info(f"Extracting seeds for {contract_address} (Not fully implemented - requires indexer)")
        
        return seeds

    def get_erc20_transfers_from(
        self, 
        tx_hash: str, 
        from_address: str
    ) -> List[dict]:
        """
        Check for Transfer events from the specified address in a transaction receipt.
        """
        if not self.w3: return []
        
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            transfers = []
            
            for log in receipt.logs:
                # Check for Transfer topic and from_address in topics[1]
                if (len(log.topics) >= 3 and 
                    log.topics[0].hex() == "0x" + ERC20_TOPIC_TRANSFER.hex() and
                    "0x" + log.topics[1].hex()[-40:].lower() == from_address.lower()):
                    
                    transfers.append({
                        "token": log.address,
                        "to": "0x" + log.topics[2].hex()[-40:],
                        "value": int(log.data.hex(), 16) if log.data else 0
                    })
            return transfers
        except Exception as e:
            logger.error(f"Error fetching logs for {tx_hash}: {e}")
            return []
