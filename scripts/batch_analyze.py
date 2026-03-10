#!/usr/bin/env python3
"""
Little Bodi Batch Analysis CLI
"""
import os
import sys
import yaml
import click
import logging
import asyncio
import csv
from datetime import datetime, timezone
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskID

# Ensure the root directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import analyze_contract
from core.reporting.models import AnalysisSummary

# Load .env
load_dotenv()

console = Console()

def load_settings(config_path="configs/settings.yaml"):
    """Load settings from YAML file."""
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

async def analyze_task(
    address: str, 
    rpc_url: str, 
    config: dict, 
    semaphore: asyncio.Semaphore, 
    progress: Progress, 
    task_id: TaskID
):
    """
    Worker task for a single contract analysis.
    """
    async with semaphore:
        try:
            # We run analyze_contract in a thread since it's mostly synchronous/blocking (Z3 etc)
            # but we use asyncio to manage concurrency of analyses.
            loop = asyncio.get_running_loop()
            
            # Fetch bytecode first if needed
            # (In a real batch scenario, we might want to pre-fetch or batch RPC calls)
            # For now, we keep it simple within the analyze_contract boundary if possible,
            # or pre-fetch here.
            
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            bytecode = await loop.run_in_executor(None, lambda: w3.eth.get_code(Web3.to_checksum_address(address)))
            
            if not bytecode or bytecode.hex() == "0x":
                progress.update(task_id, description=f"[yellow]Skipped (No code): {address}[/yellow]", completed=1)
                return {"address": address, "risk_level": "N/A", "vuln_count": 0, "loss": 0, "error": "No bytecode"}

            # Execute full pipeline
            ctx = await loop.run_in_executor(None, lambda: analyze_contract(
                bytecode_hex=bytecode.hex(),
                contract_address=address,
                rpc_url=rpc_url,
                **config
            ))
            
            if ctx.analysis_summary:
                summary: AnalysisSummary = ctx.analysis_summary
                progress.update(task_id, description=f"[green]Done: {address}[/green]", completed=1)
                return {
                    "address": address,
                    "risk_level": summary.risk_level,
                    "vuln_count": summary.vulnerability_count,
                    "loss": summary.total_estimated_loss_usd,
                    "error": ""
                }
            else:
                progress.update(task_id, description=f"[red]Failed (No summary): {address}[/red]", completed=1)
                return {"address": address, "risk_level": "error", "vuln_count": 0, "loss": 0, "error": "No summary"}

        except Exception as e:
            progress.update(task_id, description=f"[bold red]Error: {address}[/bold red]", completed=1)
            return {"address": address, "risk_level": "error", "vuln_count": 0, "loss": 0, "error": str(e)}

@click.command()
@click.option("--addresses", required=True, help="Path to text file with contract addresses (one per line)")
@click.option("--rpc", help="EVM RPC URL (overrides .env)")
@click.option("--output", help="Directory for analysis reports", default="data/results")
@click.option("--workers", type=int, default=4, help="Number of concurrent workers")
@click.option("--no-concolic", is_flag=True, help="Disable concolic execution")
def main(addresses, rpc, output, workers, no_concolic):
    """
    Little Bodi: Batch EVM Vulnerability Scanner
    """
    if not os.path.exists(addresses):
        console.print(f"[red]Error:[/red] Address file {addresses} not found.")
        sys.exit(1)
        
    with open(addresses, "r") as f:
        addr_list = [line.strip() for line in f if line.strip()]
        
    if not addr_list:
        console.print("[yellow]Warning:[/yellow] Address file is empty.")
        sys.exit(0)

    rpc_url = rpc or os.getenv("EVM_RPC_URL")
    if not rpc_url:
        console.print("[red]Error:[/red] RPC URL required for batch scan.")
        sys.exit(1)

    # Load config
    settings = load_settings()
    analysis_settings = settings.get("analysis", {})
    
    config = {
        "output_dir": output,
        "use_concolic": not no_concolic,
        "timeout_per_contract": analysis_settings.get("timeout_per_contract", 600),
        "max_symbolic_paths": analysis_settings.get("max_symbolic_paths", 10000),
        "max_path_depth": analysis_settings.get("max_path_depth", 500),
        "fallback_to_symbolic": analysis_settings.get("fallback_to_symbolic", True),
    }

    os.makedirs(output, exist_ok=True)
    summary_path = os.path.join(output, "batch_summary.csv")

    async def run_batch():
        semaphore = asyncio.Semaphore(workers)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            main_task_id = progress.add_task("[bold blue]Batch Analysis progressing...", total=len(addr_list))
            
            tasks = []
            for addr in addr_list:
                tasks.append(analyze_task(addr, rpc_url, config, semaphore, progress, main_task_id))
            
            results = await asyncio.gather(*tasks)
            
            # Save results to CSV
            with open(summary_path, "w", newline="") as csvfile:
                fieldnames = ["address", "risk_level", "vuln_count", "loss", "error"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for res in results:
                    writer.writerow(res)
            
            console.print(f"\n[bold green]Batch analysis complete![/bold green]")
            console.print(f"Summary saved to: [blue]{summary_path}[/blue]")

    try:
        asyncio.run(run_batch())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user. Exiting...[/red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
