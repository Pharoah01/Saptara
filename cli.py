#!/usr/bin/env python3
"""
SAPTARA — Automated Web Application Vulnerability Assessment Framework
Design and Implementation of an Automated Web Application Vulnerability
Assessment Framework Using Microservices Architecture
"""

import os
import re
import sys
import click
import httpx
import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.json import JSON
from rich.text import Text
from rich.rule import Rule
from rich import box
from dotenv import load_dotenv

load_dotenv()

console = Console()

DEFAULT_ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("API_KEYS", "").split(",")[0].strip()

_IST = ZoneInfo("Asia/Kolkata")

BANNER = r"""
 ____    _    ____ _____  _    ____      _
/ ___|  / \  |  _ \_   _|/ \  |  _ \   / \
\___ \ / _ \ | |_) || | / _ \ | |_) | / _ \
 ___) / ___ \|  __/ | |/ ___ \|  _ < / ___ \
|____/_/   \_\_|    |_/_/   \_\_| \_\/_/   \_\

  Automated Web Application Vulnerability Assessment Framework
  Scanner  →  Simulator  →  Validator  |  v1.0.0
"""

STAGE_COLORS = {
    "scanner":   "cyan",
    "simulator": "yellow",
    "validator": "green",
}

STATUS_ICONS = {
    "passed":     "[green]PASS[/green]",
    "blocked":    "[blue]BLKD[/blue]",
    "vulnerable": "[red]VULN[/red]",
    "failed":     "[red]FAIL[/red]",
    "error":      "[yellow]ERR [/yellow]",
    "skipped":    "[dim]SKIP[/dim]",
    "running":    "[cyan]RUN [/cyan]",
    "completed":  "[green]DONE[/green]",
    "interrupted":"[yellow]INTR[/yellow]",
}

SEVERITY_COLORS = {
    "critical": "[bold red]CRITICAL[/bold red]",
    "high":     "[red]HIGH    [/red]",
    "medium":   "[yellow]MEDIUM  [/yellow]",
    "low":      "[green]LOW     [/green]",
    "info":     "[blue]INFO    [/blue]",
    "":         "[dim]  —     [/dim]",
}

ALL_CATEGORIES = [
    "sql_injection", "xss", "path_traversal", "security_headers",
    "authentication_bypass", "rate_limiting", "bot_detection",
    "information_disclosure", "csrf_protection", "ssl_tls_security",
    "cors_misconfiguration", "file_upload_security",
    "command_injection", "xxe_injection", "ssrf", "idor", "api_enumeration",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")


def _now_ist() -> str:
    return datetime.now(_IST).strftime("%Y-%m-%d %H:%M:%S IST")


def auth_headers(ctx) -> dict:
    key = ctx.obj.get("api_key", "")
    if not key:
        console.print("[red]  [!] No API key set. Use --api-key or set API_KEYS in .env[/red]")
        raise SystemExit(1)
    return {"X-API-Key": key}


def _save_results(data: dict) -> str:
    os.makedirs("results", exist_ok=True)
    target = data.get("config", {}).get("target_url", "unknown")
    domain = re.sub(r"https?://", "", target).rstrip("/").replace("/", "_")
    domain = re.sub(r"[^\w\-.]", "_", domain)
    timestamp = datetime.now(_IST).strftime("%Y%m%d_%H%M%S")
    path = os.path.join("results", f"{domain}_{timestamp}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--orchestrator-url", default=DEFAULT_ORCHESTRATOR_URL,
              metavar="URL",
              help=f"Orchestrator URL  [default: {DEFAULT_ORCHESTRATOR_URL}]")
@click.option("--api-key", "-k", default=DEFAULT_API_KEY, envvar="API_KEYS",
              metavar="KEY",
              help="API key  [env: API_KEYS]")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.pass_context
def cli(ctx, orchestrator_url, api_key, verbose):
    """
    \b
    SAPTARA — Web Application Vulnerability Assessment
    ===================================================
    Pipeline: Scanner -> Simulator -> Validator

    \b
    Quick start:
      saptara scan -t https://target.com --wait
      saptara status <id> --watch
      saptara results <id>

    \b
    Set API_KEYS in .env to skip --api-key on every command.
    """
    ctx.ensure_object(dict)
    ctx.obj["orchestrator_url"] = orchestrator_url
    ctx.obj["api_key"] = api_key
    ctx.obj["verbose"] = verbose


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def health(ctx):
    """Check health of all services."""
    _print_banner()
    url = ctx.obj["orchestrator_url"]
    console.print(Rule("[bold]Service Health Check[/bold]"))
    console.print(f"  [dim]Endpoint : {url}/health[/dim]")
    console.print(f"  [dim]Time     : {_now_ist()}[/dim]\n")

    try:
        with console.status("  Probing services..."):
            response = httpx.get(f"{url}/health", timeout=10.0)

        if response.status_code != 200:
            console.print(f"  [red][!] Health check failed: HTTP {response.status_code}[/red]")
            return

        data = response.json()
        overall = data.get("status", "unknown")
        color = "green" if overall == "healthy" else "red"
        console.print(f"  Overall Status : [{color}]{overall.upper()}[/{color}]\n")

        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 2))
        table.add_column("SERVICE",       style="bold white",  width=20)
        table.add_column("STATUS",        width=12)
        table.add_column("RESPONSE TIME", style="dim",         width=14)
        table.add_column("ENDPOINT",      style="dim")

        svc_map = {
            "scanner":   ("Scanner",   "http://localhost:8001"),
            "validator": ("Validator", "http://localhost:8002"),
            "simulator": ("Simulator", "http://localhost:8003"),
        }

        # Orchestrator row
        rt = f"{response.elapsed.total_seconds():.3f}s"
        table.add_row("Orchestrator", "[green]HEALTHY[/green]", rt, url)

        for svc, svc_data in data.get("services", {}).items():
            st = svc_data.get("status", "unknown")
            rt = f"{svc_data.get('response_time', 0):.3f}s"
            name, ep = svc_map.get(svc, (svc.title(), "—"))
            status_str = "[green]HEALTHY[/green]" if st == "healthy" else \
                         "[red]UNHEALTHY[/red]" if st == "unhealthy" else \
                         "[yellow]UNREACHABLE[/yellow]"
            table.add_row(name, status_str, rt, ep)

        console.print(table)

    except httpx.ConnectError:
        console.print(f"  [red][!] Cannot connect to orchestrator at {url}[/red]")
        console.print("  [dim]Is the stack running?  docker compose up -d[/dim]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target",    "-t", required=True, metavar="URL",
              help="Target URL to scan  (e.g. https://example.com)")
@click.option("--intensity", "-i",
              type=click.Choice(["light", "medium", "heavy"]), default="medium",
              show_default=True, help="Scan intensity level")
@click.option("--categories", "-c", multiple=True, metavar="CATEGORY",
              help="Test category to include (repeatable). Omit for all.")
@click.option("--wait", "-w", is_flag=True,
              help="Block until pipeline completes and print results")
@click.pass_context
def scan(ctx, target, intensity, categories, wait):
    """
    Launch a full vulnerability assessment pipeline.

    \b
    Pipeline stages:
      [1] Scanner   — 17-category OWASP vulnerability scan
      [2] Simulator — multi-step exploit confirmation
      [3] Validator — security defence verification

    \b
    Examples:
      saptara scan -t https://example.com
      saptara scan -t https://example.com -i light --wait
      saptara scan -t https://example.com -c sql_injection -c xss --wait

    \b
    Available categories:
      sql_injection       xss                 path_traversal
      command_injection   xxe_injection       authentication_bypass
      api_enumeration     idor                ssl_tls_security
      information_disclosure  security_headers  cors_misconfiguration
      rate_limiting       csrf_protection     file_upload_security
      ssrf                bot_detection
    """
    _print_banner()
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    cats = list(categories) if categories else ALL_CATEGORIES

    payload = {
        "config": {
            "target_url": target,
            "test_categories": cats,
            "intensity": intensity,
            "verbose": ctx.obj["verbose"],
        },
    }

    console.print(Rule("[bold]Scan Configuration[/bold]"))
    console.print(f"  Target     : [bold cyan]{target}[/bold cyan]")
    console.print(f"  Intensity  : [yellow]{intensity}[/yellow]")
    console.print(f"  Categories : {len(cats)} selected")
    console.print(f"  Pipeline   : [cyan]Scanner[/cyan] → [yellow]Simulator[/yellow] → [green]Validator[/green]")
    console.print(f"  Started    : {_now_ist()}\n")

    try:
        with console.status("  Submitting scan to orchestrator..."):
            resp = httpx.post(f"{url}/orchestrate", json=payload,
                              headers=headers, timeout=30.0)

        if resp.status_code != 200:
            console.print(f"  [red][!] Failed (HTTP {resp.status_code}): {resp.text}[/red]")
            return

        result = resp.json()
        oid = result["orchestration_id"]

        console.print(f"  [green][+] Pipeline accepted[/green]")
        console.print(f"  Job ID     : [bold]{oid}[/bold]\n")

        if wait:
            _wait_for_completion(url, oid, headers)
        else:
            console.print(Rule())
            console.print("  [dim]Track progress:[/dim]")
            console.print(f"    python cli.py status {oid} --watch")
            console.print(f"    python cli.py results {oid}")

    except httpx.ConnectError:
        console.print(f"  [red][!] Cannot connect to orchestrator at {url}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("orchestration_id")
@click.option("--watch", "-w", is_flag=True,
              help="Refresh every 3s until scan completes")
@click.pass_context
def status(ctx, orchestration_id, watch):
    """
    Show status of a scan job.

    \b
    Examples:
      saptara status <id>
      saptara status <id> --watch
    """
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    def _fetch_and_render() -> str:
        resp = httpx.get(f"{url}/orchestration/{orchestration_id}/status",
                         headers=headers, timeout=10.0)
        if resp.status_code != 200:
            console.print(f"  [red][!] HTTP {resp.status_code}: {resp.text}[/red]")
            return "error"

        d = resp.json()
        st = d.get("status", "unknown")
        prog = d.get("progress", 0.0)
        stage = d.get("current_stage", "—")

        # Progress bar visual
        filled = int(prog / 5)   # 20 chars = 100%
        bar = "[green]" + "█" * filled + "[/green]" + "[dim]" + "░" * (20 - filled) + "[/dim]"

        console.print(Rule(f"[bold]Scan Status[/bold]  [dim]{_now_ist()}[/dim]"))
        console.print(f"  Job ID       : [bold]{orchestration_id}[/bold]")
        console.print(f"  Status       : {STATUS_ICONS.get(st, st)}  [bold]{st.upper()}[/bold]")
        console.print(f"  Progress     : {bar}  {prog:.1f}%")
        console.print(f"  Stage        : [cyan]{stage}[/cyan]")

        if d.get("started_at"):
            console.print(f"  Started      : {d['started_at']}")
        if d.get("completed_at"):
            console.print(f"  Completed    : {d['completed_at']}")
        if d.get("error"):
            console.print(f"  [red]  Error    : {d['error']}[/red]")

        svc_results = d.get("service_results", {})
        if svc_results:
            console.print()
            console.print("  Stage Results:")
            for svc in ["scanner", "simulator", "validator"]:
                svc_d = svc_results.get(svc)
                if svc_d:
                    svc_st = svc_d.get("status", "—")
                    color = STAGE_COLORS.get(svc, "white")
                    icon = "[green]✓[/green]" if svc_st == "completed" else \
                           "[red]✗[/red]" if svc_st == "failed" else "[yellow]…[/yellow]"
                    console.print(f"    {icon} [{color}]{svc.capitalize():<12}[/{color}] {svc_st}")

        return st

    try:
        if not watch:
            _print_banner()
            _fetch_and_render()
        else:
            _print_banner()
            console.print("  [dim]Live mode — Ctrl+C to stop[/dim]\n")
            while True:
                console.clear()
                _print_banner()
                st = _fetch_and_render()
                if st in ("completed", "failed", "cancelled", "error"):
                    break
                time.sleep(3)
    except KeyboardInterrupt:
        console.print("\n  [yellow][!] Watch stopped[/yellow]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("orchestration_id")
@click.option("--format", "-f", type=click.Choice(["table", "json"]),
              default="table", show_default=True, help="Output format")
@click.option("--save", "-s", metavar="PATH",
              help="Save to specific path  [default: results/<domain>_<ts>.json]")
@click.pass_context
def results(ctx, orchestration_id, format, save):
    """
    Fetch and display results of a completed scan.

    \b
    Examples:
      saptara results <id>
      saptara results <id> --format json
      saptara results <id> --save /tmp/report.json
    """
    _print_banner()
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    try:
        with console.status("  Fetching results..."):
            resp = httpx.get(f"{url}/orchestration/{orchestration_id}/results",
                             headers=headers, timeout=10.0)

        if resp.status_code != 200:
            console.print(f"  [red][!] HTTP {resp.status_code}: {resp.text}[/red]")
            return

        data = resp.json()

        if format == "json":
            console.print(JSON(json.dumps(data, indent=2, default=str)))
        else:
            _display_results_table(data)

        path = save or _save_results(data)
        if not save:
            # already saved inside _save_results
            pass
        else:
            with open(save, "w") as f:
                json.dump(data, f, indent=2, default=str)

        console.print(f"\n  [green][+] Results saved → {path}[/green]")

    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("orchestration_id")
@click.pass_context
def cancel(ctx, orchestration_id):
    """Cancel a running scan."""
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)
    try:
        resp = httpx.delete(f"{url}/orchestration/{orchestration_id}",
                            headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"  [yellow][!] {data.get('message', 'Cancelled')}[/yellow]")
        else:
            console.print(f"  [red][!] HTTP {resp.status_code}: {resp.text}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# list-scans
# ---------------------------------------------------------------------------

@cli.command(name="list-scans")
@click.pass_context
def list_scans(ctx):
    """List all scan jobs."""
    _print_banner()
    url = ctx.obj["orchestrator_url"]
    headers = auth_headers(ctx)

    try:
        with console.status("  Loading scan history..."):
            resp = httpx.get(f"{url}/orchestration", headers=headers, timeout=10.0)

        if resp.status_code != 200:
            console.print(f"  [red][!] HTTP {resp.status_code}: {resp.text}[/red]")
            return

        scans = resp.json().get("orchestrations", [])
        console.print(Rule(f"[bold]Scan History[/bold]  ({len(scans)} jobs)"))

        if not scans:
            console.print("  [dim]No scans found.[/dim]")
            return

        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 2))
        table.add_column("JOB ID",    style="cyan",  width=14)
        table.add_column("TARGET",    style="bold",  width=35)
        table.add_column("STATUS",    width=12)
        table.add_column("PROGRESS",  width=8)
        table.add_column("STAGE",     style="dim",   width=12)
        table.add_column("STARTED",   style="dim")

        for s in scans:
            oid = s.get("orchestration_id", "")[:12] + "…"
            target = s.get("config", {}).get("target_url", "—")
            if len(target) > 33:
                target = target[:30] + "…"
            st = s.get("status", "—")
            prog = f"{s.get('progress', 0):.0f}%"
            stage = s.get("current_stage", "—")
            started = str(s.get("started_at", "—"))[:19]
            status_str = "[green]COMPLETED[/green]" if st == "completed" else \
                         "[red]FAILED[/red]"    if st == "failed"    else \
                         "[cyan]RUNNING[/cyan]"  if st == "running"   else \
                         f"[dim]{st.upper()}[/dim]"
            table.add_row(oid, target, status_str, prog, stage, started)

        console.print(table)

    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")


# ---------------------------------------------------------------------------
# _wait_for_completion
# ---------------------------------------------------------------------------

def _wait_for_completion(url: str, oid: str, headers: dict):
    console.print(Rule("[bold]Pipeline Execution[/bold]"))

    stage_order = ["scanner", "simulator", "validator"]
    stage_done: Dict[str, bool] = {s: False for s in stage_order}

    with Progress(
        SpinnerColumn(),
        TextColumn("  [bold]{task.description}[/bold]"),
        BarColumn(bar_width=30),
        TextColumn("{task.percentage:>5.1f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Initialising...", total=100)

        while True:
            try:
                resp = httpx.get(f"{url}/orchestration/{oid}/status",
                                 headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    d = resp.json()
                    st = d.get("status", "")
                    prog = d.get("progress", 0)
                    stage = d.get("current_stage", "")

                    # Stage label
                    stage_label = {
                        "scanner":   "[cyan]Stage 1/3  Scanner[/cyan]",
                        "simulator": "[yellow]Stage 2/3  Simulator[/yellow]",
                        "validator": "[green]Stage 3/3  Validator[/green]",
                        "done":      "[green]Finalising[/green]",
                    }.get(stage, stage)

                    progress.update(task, completed=prog,
                                    description=stage_label or "Running...")

                    # Print stage completion lines
                    svc_results = d.get("service_results", {})
                    for svc in stage_order:
                        if svc in svc_results and not stage_done[svc]:
                            svc_st = svc_results[svc].get("status", "")
                            color = STAGE_COLORS.get(svc, "white")
                            icon = "[green]✓[/green]" if svc_st == "completed" else "[red]✗[/red]"
                            progress.console.print(
                                f"  {icon} [{color}]{svc.capitalize():<12}[/{color}]  {svc_st.upper()}"
                            )
                            stage_done[svc] = True

                    if st in ("completed", "failed", "cancelled"):
                        if st == "failed" and d.get("error"):
                            progress.console.print(
                                f"\n  [red][!] Pipeline failed: {d['error']}[/red]"
                            )
                        break
            except Exception:
                break
            time.sleep(2)

    # Final summary
    try:
        resp = httpx.get(f"{url}/orchestration/{oid}/results",
                         headers=headers, timeout=10.0)
        if resp.status_code != 200:
            return
        data = resp.json()
        _display_results_table(data)
        path = _save_results(data)
        console.print(f"\n  [green][+] Results saved → {path}[/green]")
    except Exception as e:
        console.print(f"  [red][!] Could not fetch results: {e}[/red]")


# ---------------------------------------------------------------------------
# _display_results_table
# ---------------------------------------------------------------------------

def _display_results_table(data: Dict[str, Any]):
    total_tests = 0
    total_vulns = 0
    total_failed = 0

    for svc in ["scanner", "simulator", "validator"]:
        svc_data = data.get("service_results", {}).get(svc)
        if not svc_data:
            continue

        results = svc_data.get("results", {}).get("results", [])
        color = STAGE_COLORS.get(svc, "white")

        console.print()
        console.print(Rule(
            f"[bold {color}]  {svc.upper()}  [/bold {color}]"
            f"[dim]  {len(results)} tests[/dim]"
        ))

        if not results:
            st = svc_data.get("status", "unknown")
            console.print(f"  [dim]No results  (status: {st})[/dim]")
            continue

        table = Table(
            box=box.SIMPLE_HEAD,
            show_edge=False,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("STATUS",   width=6,  no_wrap=True)
        table.add_column("SEV",      width=10, no_wrap=True)
        table.add_column("CATEGORY", width=28, style="dim", no_wrap=True)
        table.add_column("TEST",     width=38)
        table.add_column("DETAILS",  style="dim")

        for r in results:
            st  = r.get("status", "")
            sev = r.get("vulnerability_level") or ""
            det = r.get("details", "") or ""
            table.add_row(
                STATUS_ICONS.get(st, st),
                SEVERITY_COLORS.get(sev, SEVERITY_COLORS[""]),
                r.get("category", ""),
                r.get("test_name", ""),
                det[:72] + ("…" if len(det) > 72 else ""),
            )

        console.print(table)

        vuln_c  = sum(1 for r in results if r.get("status") == "vulnerable")
        fail_c  = sum(1 for r in results if r.get("status") == "failed")
        pass_c  = sum(1 for r in results if r.get("status") in ("passed", "blocked"))
        total_tests += len(results)
        total_vulns += vuln_c
        total_failed += fail_c

        console.print(
            f"  [green]{pass_c} passed[/green]  "
            f"[red]{vuln_c} vulnerable[/red]  "
            f"[yellow]{fail_c} failed[/yellow]"
        )

    # Summary bar
    console.print()
    console.print(Rule("[bold]Summary[/bold]"))
    console.print(f"  Total tests      : {total_tests}")
    console.print(f"  Vulnerable       : [red]{total_vulns}[/red]")
    console.print(f"  Failed checks    : [yellow]{total_failed}[/yellow]")
    console.print(f"  Completed at     : {_now_ist()}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli(prog_name="saptara")
