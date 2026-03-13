#!/usr/bin/env python3
"""
Project SAPTARA CLI Client
Seven relics. Seven roles. One system.

Interactive command-line interface for the SAPTARA security testing framework
"""

import click
import httpx
import json
import time
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.json import JSON

console = Console()

DEFAULT_ORCHESTRATOR_URL = "http://localhost:8000"
DEFAULT_SCANNER_URL = "http://localhost:8001"
DEFAULT_VALIDATOR_URL = "http://localhost:8002"
DEFAULT_SIMULATOR_URL = "http://localhost:8003"


@click.group()
@click.option('--orchestrator-url', default=DEFAULT_ORCHESTRATOR_URL, help='The Orchestrator (Conductor) service URL')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, orchestrator_url, verbose):
    """🛡️ Project SAPTARA CLI - Seven relics. Seven roles. One system."""
    ctx.ensure_object(dict)
    ctx.obj['orchestrator_url'] = orchestrator_url
    ctx.obj['verbose'] = verbose


@cli.command()
@click.pass_context
def health(ctx):
    """Check health of all seven relics"""
    orchestrator_url = ctx.obj['orchestrator_url']
    
    with console.status("[bold green]Checking the seven relics..."):
        try:
            response = httpx.get(f"{orchestrator_url}/health", timeout=10.0)
            if response.status_code == 200:
                health_data = response.json()
                
                table = Table(title="🛡️ SAPTARA - The Seven Relics Status")
                table.add_column("Relic", style="cyan")
                table.add_column("Role", style="yellow")
                table.add_column("Status", style="bold")
                table.add_column("Response Time", style="magenta")
                
                table.add_row("The Orchestrator", "The Conductor", "✅ Healthy", f"{response.elapsed.total_seconds():.2f}s")
                
                relic_roles = {
                    'scanner': ('The Scanner', 'The Seeker'),
                    'validator': ('The Validator', 'The Guardian'),
                    'simulator': ('The Simulator', 'The Challenger'),
                    'database': ('The Keeper', 'The Memory'),
                    'redis': ('The Messenger', 'The Swift'),
                    'prometheus': ('The Observer', 'The Watcher')
                }
                
                for service_name, service_data in health_data.get('services', {}).items():
                    status = service_data.get('status', 'unknown')
                    response_time = service_data.get('response_time', 0)
                    
                    relic_name, role = relic_roles.get(service_name, (service_name.title(), 'Unknown Role'))
                    
                    if status == 'healthy':
                        status_display = "✅ Healthy"
                    elif status == 'unhealthy':
                        status_display = "❌ Unhealthy"
                    else:
                        status_display = "🔴 Unreachable"
                    
                    table.add_row(relic_name, role, status_display, f"{response_time:.2f}s")
                
                console.print(table)
                console.print("\n[italic]In unity, the seven relics find their strength.[/italic]")
            else:
                console.print(f"[red]❌ Failed to get health status: {response.status_code}[/red]")
                
        except Exception as e:
            console.print(f"[red]❌ Error checking health: {e}[/red]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--categories', '-c', multiple=True, help='Test categories to run')
@click.option('--intensity', '-i', type=click.Choice(['light', 'medium', 'heavy']), default='medium', help='Test intensity')
@click.option('--services', '-s', multiple=True, default=['scanner'], help='Services to use')
@click.option('--parallel', is_flag=True, default=True, help='Run services in parallel')
@click.option('--wait', '-w', is_flag=True, help='Wait for completion and show results')
@click.pass_context
def scan(ctx, target, categories, intensity, services, parallel, wait):
    """Start a security scan"""
    orchestrator_url = ctx.obj['orchestrator_url']
    
    if not categories:
        categories = ['sql_injection', 'xss', 'path_traversal', 'security_headers']
    
    request_data = {
        "config": {
            "target_url": target,
            "test_categories": list(categories),
            "intensity": intensity,
            "verbose": ctx.obj['verbose']
        },
        "services": list(services),
        "parallel": parallel
    }
    
    console.print(Panel(f"🛡️ SAPTARA initiating protection for [bold cyan]{target}[/bold cyan]"))
    console.print(f"Categories: {', '.join(categories)}")
    console.print(f"Intensity: {intensity}")
    console.print(f"Relics: {', '.join(services)}")
    console.print("[italic]Seven relics working in unity...[/italic]")
    
    try:
        with console.status("[bold green]The relics are awakening..."):
            response = httpx.post(
                f"{orchestrator_url}/orchestrate",
                json=request_data,
                timeout=30.0
            )
        
        if response.status_code == 200:
            result = response.json()
            orchestration_id = result['orchestration_id']
            
            console.print(f"[green]✅ SAPTARA protection initiated successfully![/green]")
            console.print(f"Orchestration ID: [bold]{orchestration_id}[/bold]")
            
            if wait:
                wait_for_completion(orchestrator_url, orchestration_id)
            else:
                console.print(f"\n💡 To check status: [bold]saptara status {orchestration_id}[/bold]")
                console.print(f"💡 To get results: [bold]saptara results {orchestration_id}[/bold]")
        else:
            console.print(f"[red]❌ Failed to start scan: {response.status_code}[/red]")
            console.print(response.text)
            
    except Exception as e:
        console.print(f"[red]❌ Error starting scan: {e}[/red]")


@cli.command()
@click.argument('orchestration_id')
@click.pass_context
def status(ctx, orchestration_id):
    """Check status of a scan"""
    orchestrator_url = ctx.obj['orchestrator_url']
    
    try:
        response = httpx.get(f"{orchestrator_url}/orchestration/{orchestration_id}/status", timeout=10.0)
        
        if response.status_code == 200:
            status_data = response.json()
            
            table = Table(title=f"📊 Scan Status: {orchestration_id}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="bold")
            
            table.add_row("Status", status_data.get('status', 'unknown'))
            table.add_row("Progress", f"{status_data.get('progress', 0):.1f}%")
            table.add_row("Started", status_data.get('started_at', 'unknown'))
            
            if status_data.get('completed_at'):
                table.add_row("Completed", status_data['completed_at'])
            
            console.print(table)
            
            service_results = status_data.get('service_results', {})
            if service_results:
                console.print("\n🔧 Service Results:")
                for service_name, service_data in service_results.items():
                    service_status = service_data.get('status', 'unknown')
                    console.print(f"  {service_name}: {service_status}")
        else:
            console.print(f"[red]❌ Failed to get status: {response.status_code}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Error getting status: {e}[/red]")


@cli.command()
@click.argument('orchestration_id')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table', help='Output format')
@click.option('--save', '-s', help='Save results to file')
@click.pass_context
def results(ctx, orchestration_id, format, save):
    """Get results of a scan"""
    orchestrator_url = ctx.obj['orchestrator_url']
    
    try:
        response = httpx.get(f"{orchestrator_url}/orchestration/{orchestration_id}/results", timeout=10.0)
        
        if response.status_code == 200:
            results_data = response.json()
            
            if format == 'json':
                console.print(JSON(json.dumps(results_data, indent=2)))
            else:
                display_results_table(results_data)
            
            if save:
                with open(save, 'w') as f:
                    json.dump(results_data, f, indent=2)
                console.print(f"[green]💾 Results saved to {save}[/green]")
                
        else:
            console.print(f"[red]❌ Failed to get results: {response.status_code}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Error getting results: {e}[/red]")


@cli.command()
@click.pass_context
def list_scans(ctx):
    """List all scans"""
    orchestrator_url = ctx.obj['orchestrator_url']
    
    try:
        response = httpx.get(f"{orchestrator_url}/orchestration", timeout=10.0)
        
        if response.status_code == 200:
            scans_data = response.json()
            scans = scans_data.get('orchestrations', [])
            
            if scans:
                table = Table(title="📋 All Scans")
                table.add_column("ID", style="cyan")
                table.add_column("Target", style="bold")
                table.add_column("Status", style="magenta")
                table.add_column("Started", style="green")
                
                for scan in scans:
                    table.add_row(
                        scan.get('orchestration_id', '')[:8] + '...',
                        scan.get('config', {}).get('target_url', 'unknown'),
                        scan.get('status', 'unknown'),
                        scan.get('started_at', 'unknown')
                    )
                
                console.print(table)
            else:
                console.print("[yellow]No scans found[/yellow]")
        else:
            console.print(f"[red]❌ Failed to list scans: {response.status_code}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Error listing scans: {e}[/red]")


def wait_for_completion(orchestrator_url: str, orchestration_id: str):
    """Wait for scan completion and show progress"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running security scan...", total=100)
        
        while True:
            try:
                response = httpx.get(f"{orchestrator_url}/orchestration/{orchestration_id}/status", timeout=10.0)
                
                if response.status_code == 200:
                    status_data = response.json()
                    status = status_data.get('status', 'unknown')
                    progress_value = status_data.get('progress', 0)
                    
                    progress.update(task, completed=progress_value)
                    
                    if status in ['completed', 'failed', 'cancelled']:
                        break
                        
                time.sleep(2)
                
            except Exception as e:
                console.print(f"[red]❌ Error checking status: {e}[/red]")
                break
    
    console.print(f"\n[green]✅ Scan completed![/green]")
    console.print(f"Getting results for {orchestration_id}...")
    
    try:
        response = httpx.get(f"{orchestrator_url}/orchestration/{orchestration_id}/results", timeout=10.0)
        if response.status_code == 200:
            results_data = response.json()
            display_results_table(results_data)
    except Exception as e:
        console.print(f"[red]❌ Error getting final results: {e}[/red]")


def display_results_table(results_data: Dict[str, Any]):
    """Display results in a formatted table"""
    service_results = results_data.get('service_results', {})
    
    for service_name, service_data in service_results.items():
        console.print(f"\n🔧 {service_name.title()} Results:")
        
        results = service_data.get('results', {}).get('results', [])
        if results:
            table = Table()
            table.add_column("Category", style="cyan")
            table.add_column("Test", style="bold")
            table.add_column("Status", style="magenta")
            table.add_column("Details", style="green")
            
            for result in results[:10]:  # Show first 10 results
                status = result.get('status', 'unknown')
                status_display = {
                    'passed': '✅ Passed',
                    'blocked': '🛡️ Blocked',
                    'vulnerable': '🚨 Vulnerable',
                    'failed': '❌ Failed',
                    'error': '⚠️ Error'
                }.get(status, status)
                
                table.add_row(
                    result.get('category', ''),
                    result.get('test_name', ''),
                    status_display,
                    result.get('details', '')[:50] + '...' if result.get('details') else ''
                )
            
            console.print(table)
            
            if len(results) > 10:
                console.print(f"... and {len(results) - 10} more results")
        else:
            console.print("[yellow]No results found[/yellow]")


if __name__ == '__main__':
    cli()