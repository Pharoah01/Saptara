#!/usr/bin/env python3
"""
Project SAPTARA CLI Client
Seven relics. Seven roles. One system.
"""

import os
import re
import click
import httpx
import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.json import JSON
from dotenv import load_dotenv

load_dotenv()

console = Console()

DEFAULT_ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("API_KEYS", "").split(",")[0].strip()


def auth_headers(ctx) -> dict:
    """Return the X-API-Key header dict from context."""
    key = ctx.obj.get("api_key", "")
    if not key:
        console.print("[red]❌ No API key set. Use --api-key or set API_KEYS in .env[/red]")
        raise SystemExit(1)
    return {"X-API-Key": key}


@click.group()
@click.option("--orchestrator-url", default=DEFAULT_ORCHESTRATOR_URL,
              help="Orchestrator service URL (default: $ORCHESTRATOR_URL or http://localhost:8000)")
@click.option("--api-key", "-k", default=DEFAULT_API_KEY, envvar="API_KEYS",
              help="API key for authentication (default: first key in $API_KEYS)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, orchestrator_url, api_key, verbose):
    """🛡️ Project SAPTARA CLI — Seven relics. Seven roles. One system."""
    ctx.ensure_object(dict)
    ctx.obj["orchestrator_url"] = orchestrator_url
    ctx.obj["api_key"] = api_key
    ctx.obj["verbose"] = verbose



@cli.command()
@click.pass_context
def health(ctx):
    """Check health of all seven relics"""
    url = ctx.obj["orchestrator_url"]
    with console.status("[bold green]Checking the seven relics..."):
        try:
            response = httpx.get(f"{url}/health", timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                table = Table(title="🛡️ SAPTARA — The Seven Relics Status")
                table.add_column("Relic", style="cyan")
                table.add_column("Role", style="yellow")
                table.add_column("Status", style="bold")
                table.add_column("Response Time", style="magenta")

                table.add_row("The Orchestrator", "The Conductor", "✅ Healthy",
                              f"{response.elapsed.total_seconds():.2f}s")

                relic_roles = {
                    "scanner":    ("The Scanner",   "The Seeker"),
                    "validator":  ("The Validator",  "The Guardian"),
                    "simulator":  ("The Simulator",  "The Challenger"),
                    "database":   ("The Keeper",     "The Memory"),
                    "redis":      ("The Messenger",  "The Swift"),
                    "prometheus": ("The Observer",   "The Watcher"),
                }
                for svc, svc_data in data.get("services", {}).items():
                    st = svc_data.get("status", "unknown")
                    rt = svc_data.get("response_time", 0)
                    name, role = relic_roles.get(svc, (svc.title(), "Unknown"))
                    icon = "✅" if st == "healthy" else ("❌" if st == "unhealthy" else "🔴")
                    table.add_row(name, role, f"{icon} {st.title()}", f"{rt:.2f}s")

                console.print(table)
                console.print("\n[italic]In unity, the seven relics find their strength.[/italic]")
            else:
                console.print(f"[red]❌ Health check failed: {response.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")



@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--categories", "-c", multiple=True,
              help="Test categories (repeatable). Default: all categories")
@click.option("--intensity", "-i",
              type=click.Choice(["light", "medium", "heavy"]), default="medium",
              help="Test intensity level")
@click.option("--wait", "-w", is_flag=True,
              help="Wait for completion and print results")
@click.pass_context
def scan(ctx, target, categories, intensity, wait):
    """Start a security scan against TARGET (Scanner → Simulator → Validator)"""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    if not categories:
        categories = [
            "sql_injection", "xss", "path_traversal", "security_headers",
            "authentication_bypass", "rate_limiting", "bot_detection",
            "information_disclosure", "csrf_protection", "ssl_tls_security",
            "cors_misconfiguration", "file_upload_security",
        ]

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    payload = {
        "config": {
            "target_url": target,
            "test_categories": list(categories),
            "intensity": intensity,
            "verbose": ctx.obj["verbose"],
        },
    }

    console.print(Panel(
        f"🛡️ SAPTARA initiating scan for [bold cyan]{target}[/bold cyan]\n"
        f"Pipeline: [yellow]Scanner[/yellow] → [yellow]Simulator[/yellow] → [yellow]Validator[/yellow]"
    ))
    console.print(f"Categories : {', '.join(categories)}")
    console.print(f"Intensity  : {intensity}")

    try:
        with console.status("[bold green]The relics are awakening..."):
            resp = httpx.post(f"{url}/orchestrate", json=payload,
                              headers=headers, timeout=30.0)

        if resp.status_code == 200:
            result = resp.json()
            oid = result["orchestration_id"]
            console.print(f"\n[green]✅ Pipeline started[/green]")
            console.print(f"Orchestration ID: [bold]{oid}[/bold]")

            if wait:
                _wait_for_completion(url, oid, headers)
            else:
                console.print(f"\n  python cli.py status {oid}")
                console.print(f"  python cli.py results {oid}")
        else:
            console.print(f"[red]❌ Failed ({resp.status_code}): {resp.text}[/red]")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")



@cli.command()
@click.argument("orchestration_id")
@click.option("--watch", "-w", is_flag=True, help="Poll every 3s until completed/failed")
@click.pass_context
def status(ctx, orchestration_id, watch):
    """Check status of a scan"""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    def _fetch_and_print():
        resp = httpx.get(f"{url}/orchestration/{orchestration_id}/status",
                         headers=headers, timeout=10.0)
        if resp.status_code != 200:
            console.print(f"[red]❌ {resp.status_code}: {resp.text}[/red]")
            return None
        d = resp.json()
        table = Table(title="📊 Scan Status")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="bold")
        table.add_row("Orchestration ID", orchestration_id)
        table.add_row("Status", d.get("status", "unknown"))
        table.add_row("Progress", f"{d.get('progress', 0):.1f}%")
        table.add_row("Current Stage", d.get("current_stage", "—"))
        if d.get("error"):
            table.add_row("Error", f"[red]{d['error']}[/red]")
        if d.get("started_at"):
            table.add_row("Started", str(d["started_at"]))
        if d.get("completed_at"):
            table.add_row("Completed", str(d["completed_at"]))
        console.print(table)
        for svc, svc_data in d.get("service_results", {}).items():
            console.print(f"  {svc}: {svc_data.get('status', 'unknown')}")
        return d.get("status")

    try:
        if not watch:
            _fetch_and_print()
        else:
            console.print("[dim]Watching — press Ctrl+C to stop[/dim]\n")
            while True:
                console.clear()
                st = _fetch_and_print()
                if st in ("completed", "failed", "cancelled"):
                    break
                time.sleep(3)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped watching[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")



@cli.command()
@click.argument("orchestration_id")
@click.option("--format", "-f", type=click.Choice(["table", "json"]),
              default="table", help="Output format")
@click.option("--save", "-s", help="Save results to a specific path (default: results/<domain>_<timestamp>.json)")
@click.pass_context
def results(ctx, orchestration_id, format, save):
    """Get results of a completed scan"""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)
    try:
        resp = httpx.get(f"{url}/orchestration/{orchestration_id}/results",
                         headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if format == "json":
                console.print(JSON(json.dumps(data, indent=2, default=str)))
            else:
                _display_results_table(data)

            # Determine save path — always save, default to results/ dir
            if not save:
                os.makedirs("results", exist_ok=True)
                target = data.get("config", {}).get("target_url", "unknown")
                domain = re.sub(r"https?://", "", target).rstrip("/").replace("/", "_")
                domain = re.sub(r"[^\w\-.]", "_", domain)
                timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y%m%d_%H%M%S")
                save = os.path.join("results", f"{domain}_{timestamp}.json")

            with open(save, "w") as f:
                json.dump(data, f, indent=2, default=str)
            console.print(f"[green]💾 Saved to {save}[/green]")
        else:
            console.print(f"[red]❌ {resp.status_code}: {resp.text}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")



@cli.command()
@click.argument("orchestration_id")
@click.pass_context
def cancel(ctx, orchestration_id):
    """Cancel a running scan"""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)
    try:
        resp = httpx.delete(
            f"{url}/orchestration/{orchestration_id}",
            headers=headers, timeout=10.0
        )
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[yellow]🛑 {data.get('message')}[/yellow]")
        else:
            console.print(f"[red]❌ {resp.status_code}: {resp.text}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")



@cli.command(name="list-scans")
@click.pass_context
def list_scans(ctx):
    """List all scans"""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)
    try:
        resp = httpx.get(f"{url}/orchestration", headers=headers, timeout=10.0)
        if resp.status_code == 200:
            scans = resp.json().get("orchestrations", [])
            if scans:
                table = Table(title="📋 All Scans")
                table.add_column("ID", style="cyan")
                table.add_column("Target", style="bold")
                table.add_column("Status", style="magenta")
                table.add_column("Started", style="green")
                for s in scans:
                    table.add_row(
                        s.get("orchestration_id", "")[:12] + "...",
                        s.get("config", {}).get("target_url", ""),
                        s.get("status", ""),
                        str(s.get("started_at", "")),
                    )
                console.print(table)
            else:
                console.print("[yellow]No scans found[/yellow]")
        else:
            console.print(f"[red]❌ {resp.status_code}: {resp.text}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")



def _wait_for_completion(url: str, oid: str, headers: dict):
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Scanning...", total=100)
        while True:
            try:
                resp = httpx.get(f"{url}/orchestration/{oid}/status",
                                 headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    d = resp.json()
                    progress.update(task, completed=d.get("progress", 0),
                                    description=f"Scanning... {d.get('status', '')}")
                    if d.get("status") in ("completed", "failed", "cancelled"):
                        if d.get("status") == "failed" and d.get("error"):
                            console.print(f"\n[red]❌ Pipeline failed: {d['error']}[/red]")
                        break
            except Exception:
                break
            time.sleep(2)

    console.print("\n[green]✅ Scan complete[/green]")
    try:
        resp = httpx.get(f"{url}/orchestration/{oid}/results",
                         headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            _display_results_table(data)
            # Auto-save to results/
            os.makedirs("results", exist_ok=True)
            target = data.get("config", {}).get("target_url", "unknown")
            domain = re.sub(r"https?://", "", target).rstrip("/").replace("/", "_")
            domain = re.sub(r"[^\w\-.]", "_", domain)
            timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y%m%d_%H%M%S")
            path = os.path.join("results", f"{domain}_{timestamp}.json")
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            console.print(f"[green]💾 Saved to {path}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Could not fetch results: {e}[/red]")


def _display_results_table(data: Dict[str, Any]):
    total_vulns = 0
    for svc in ["scanner", "simulator", "validator"]:
        svc_data = data.get("service_results", {}).get(svc)
        if not svc_data:
            continue

        console.print(f"\n[bold cyan]── {svc.title()} ──[/bold cyan]")

        results = svc_data.get("results", {}).get("results", [])
        if not results:
            status = svc_data.get("status", "unknown")
            console.print(f"[yellow]  No results (status: {status})[/yellow]")
            continue

        table = Table(show_lines=True)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Test", style="white")
        table.add_column("Status", style="bold", no_wrap=True)
        table.add_column("Severity", style="magenta", no_wrap=True)
        table.add_column("Details", style="dim")

        status_icons = {
            "passed":     "✅ Passed",
            "blocked":    "🛡️  Blocked",
            "vulnerable": "🚨 Vulnerable",
            "failed":     "❌ Failed",
            "error":      "⚠️  Error",
            "skipped":    "⏭️  Skipped",
        }
        severity_colors = {
            "critical": "[red]CRITICAL[/red]",
            "high":     "[orange3]HIGH[/orange3]",
            "medium":   "[yellow]MEDIUM[/yellow]",
            "low":      "[green]LOW[/green]",
            "info":     "[blue]INFO[/blue]",
        }

        for r in results:
            st = r.get("status", "")
            sev = r.get("vulnerability_level") or ""
            details = r.get("details", "") or ""
            table.add_row(
                r.get("category", ""),
                r.get("test_name", ""),
                status_icons.get(st, st),
                severity_colors.get(sev, sev),
                details[:80] + ("…" if len(details) > 80 else ""),
            )

        console.print(table)
        vuln_count = sum(1 for r in results if r.get("status") == "vulnerable")
        total_vulns += vuln_count
        console.print(f"  {len(results)} tests — [red]{vuln_count} vulnerable[/red]")

    console.print(f"\n[bold]Total vulnerabilities found: [red]{total_vulns}[/red][/bold]")


if __name__ == "__main__":
    cli()
