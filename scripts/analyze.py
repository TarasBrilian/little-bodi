#!/usr/bin/env python3
"""
Little Bodi Single-Contract Analysis CLI
"""
import os
import sys
import yaml
import click
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Ensure the root directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import analyze_contract, AnalysisConfig
from core.reporting.models import AnalysisSummary

# Load .env
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("little_bodi")

console = Console()

def load_settings(config_path="configs/settings.yaml"):
    """Load settings from YAML file."""
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

@click.command()
@click.option("--address", help="Contract address to analyze (for RPC mode)")
@click.option("--bytecode-file", help="Local file containing contract bytecode (hex)")
@click.option("--rpc", help="EVM RPC URL (overrides .env)")
@click.option("--output", help="Directory for analysis reports", default="data/results")
@click.option("--block-number", type=int, help="Block number to fork from (optional)")
@click.option("--no-concolic", is_flag=True, help="Disable concolic execution and use pure symbolic execution")
@click.option("--bypass-access-control", is_flag=True, help="Bypass strict msg.sender/tx.origin checks to analyze protected logic")
def main(address, bytecode_file, rpc, output, block_number, no_concolic, bypass_access_control):
    """
    Little Bodi: Advanced EVM Asset Management Vulnerability Scanner
    """
    # 1. Determine bytecode
    bytecode_hex = None
    if bytecode_file:
        if not os.path.exists(bytecode_file):
            console.print(f"[red]Error:[/red] Bytecode file {bytecode_file} not found.")
            sys.exit(1)
        with open(bytecode_file, "r") as f:
            bytecode_hex = f.read().strip()
    
    # 2. Determine RPC
    rpc_url = rpc or os.getenv("EVM_RPC_URL")
    
    # 3. Load config and merge
    settings = load_settings()
    analysis_settings = settings.get("analysis", {})
    
    # Setup analysis config
    config = {
        "output_dir": output,
        "use_concolic": not no_concolic,
        # Load from YAML if available
        "timeout_per_contract": analysis_settings.get("timeout_per_contract", 30),
        "max_symbolic_paths": analysis_settings.get("max_symbolic_paths", 300),
        "max_path_depth": analysis_settings.get("max_path_depth", 75),
        "fallback_to_symbolic": analysis_settings.get("fallback_to_symbolic", True),
        "stop_on_first_vuln": analysis_settings.get("stop_on_first_vuln", True),
        "bypass_access_control": bypass_access_control,
    }

    # 4. Handle missing address/bytecode
    if not address and not bytecode_hex:
        console.print("[red]Error:[/red] Must provide either --address or --bytecode-file.")
        sys.exit(1)

    # 5. Run analysis with progress indicators
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(description=f"Analyzing {address or 'local bytecode'}...", total=None)
            
            # If we don't have bytecode, we MUST have an address + RPC
            if not bytecode_hex:
                if not rpc_url:
                    console.print("[red]Error:[/red] RPC URL required to fetch bytecode for address scan.")
                    sys.exit(1)
                
                # Fetching bytecode from RPC (pipeline.analyze_contract handles this via web3)
                # However, analyze_contract() expects bytecode_hex.
                # Let's adjust to allow analyze_contract to take address instead in the future,
                # or fetch it here.
                from web3 import Web3
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                try:
                    bytecode = w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=block_number or "latest")
                    bytecode_hex = bytecode.hex()
                except Exception as e:
                    console.print(f"[red]Error fetching bytecode from RPC:[/red] {e}")
                    sys.exit(1)

            if not bytecode_hex or bytecode_hex == "0x":
                 console.print("[red]Error:[/red] No bytecode found for address or empty bytecode.")
                 sys.exit(1)

            # Execution
            ctx = analyze_contract(
                bytecode_hex=bytecode_hex,
                contract_address=address,
                rpc_url=rpc_url,
                block_number=block_number,
                **config
            )

        # 6. Show summary
        if ctx.analysis_summary:
            summary: AnalysisSummary = ctx.analysis_summary
            
            risk_colors = {
                "none": "green",
                "low": "yellow",
                "medium": "orange3",
                "high": "red",
                "critical": "bold red",
            }
            color = risk_colors.get(summary.risk_level, "white")
            
            console.print(Panel(
                f"[bold]Little Bodi Analysis Complete[/bold]\n"
                f"Contract: {summary.contract_address}\n"
                f"Risk Level: [{color}]{summary.risk_level.upper()}[/]\n"
                f"Vulnerabilities: {summary.vulnerability_count}\n"
                f"Confirmed Exploits: {summary.confirmed_exploit_count}\n"
                f"Estimated Loss: [bold blue]${summary.total_estimated_loss_usd:,.0f}[/] (lower bound)\n"
                f"Duration: {summary.analysis_duration_seconds:.1f}s",
                title="Analysis Result",
                border_style=color,
            ))
            
            if ctx.report_files:
                console.print("\n[bold]Reports generated:[/bold]")
                for f in ctx.report_files:
                    console.print(f" - {f}")
        else:
            console.print("[yellow]Warning:[/yellow] Analysis completed but no summary was generated.")

    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user. Exiting...[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Critical Error:[/bold red] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
