#!/usr/bin/env python3
"""
IR-Agent CLI — Command-Line Interface for the Incident Response Agent API

Usage:
    python cli.py status            — server health
    python cli.py query "text"      — agent query (streaming)
    python cli.py tools             — list all agent tools
    python cli.py metrics           — live metrics dashboard
    python cli.py ioc <ip/domain>   — quick IoC check
    python cli.py mitre <T1003>     — MITRE technique lookup
    python cli.py investigate <id>  — start full investigation
    python cli.py assess            — interactive threat assessment
    python cli.py shell             — interactive REPL
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

import click
import httpx
from dotenv import load_dotenv

# Force UTF-8 output on Windows (avoids cp1251 emoji encoding errors)
import io as _io
import sys as _sys
if hasattr(_sys.stdout, "buffer"):
    _sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(_sys.stderr, "buffer"):
    _sys.stderr = _io.TextIOWrapper(_sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# ── Config ─────────────────────────────────────────────────────────────────
load_dotenv()

DEFAULT_BASE  = os.getenv("IR_AGENT_URL",   "http://localhost:9000")
DEFAULT_TOKEN = os.getenv("MY_API_TOKEN",   "WAhV9fBn2sRyuOXLv6MNlwT4gHFbYKPS")
TIMEOUT       = 120.0

console = Console(force_terminal=True, legacy_windows=False)

BANNER = """[bold cyan]
  ██╗██████╗       █████╗  ██████╗ ███████╗███╗   ██╗████████╗
  ██║██╔══██╗     ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
  ██║██████╔╝     ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
  ██║██╔══██╗     ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
  ██║██║  ██║     ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═╝╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝[/bold cyan]
[dim]  AI-powered Cyber Incident Response Agent  ·  CLI v1.0.0[/dim]
"""

# ── HTTP client factory ─────────────────────────────────────────────────────
def make_client(base: str, token: str) -> httpx.Client:
    return httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT,
    )


# ── Severity color helper ────────────────────────────────────────────────────
def sev_color(sev: str) -> str:
    return {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "green",
        "info":     "cyan",
        "clean":    "green",
        "malicious":"bold red",
        "suspicious":"yellow",
    }.get(str(sev).lower(), "white")


def verdict_icon(v: str) -> str:
    v = str(v).upper()
    if "MALICIOUS" in v:   return "🔴"
    if "SUSPICIOUS" in v:  return "🟡"
    if "CLEAN" in v:       return "🟢"
    return "⚪"


# ── Render streaming step ────────────────────────────────────────────────────
def render_step(step: dict, console: Console) -> None:
    step_n = step.get("step", "?")
    action = step.get("action")
    thought = step.get("thought", "")
    obs     = step.get("observation", "")

    # Step header
    hdr = Text()
    hdr.append(f" STEP {step_n} ", style="bold black on cyan")
    if action:
        hdr.append(f"  ⚡ {action}", style="bold cyan")

    # Thought (italic muted)
    body = Text()
    if thought:
        snippet = thought[:280] + ("…" if len(thought) > 280 else "")
        body.append("💭 ", style="dim")
        body.append(snippet, style="dim italic")

    # Observation
    if obs:
        body.append("\n\n")
        body.append("👁  ", style="green")
        body.append(str(obs)[:500], style="green")

    console.print()
    console.print(hdr)
    if body.plain:
        console.print(Panel(body, border_style="dim", padding=(0, 1)))


def render_answer(data: dict, console: Console) -> None:
    answer    = data.get("answer", "")
    tools     = data.get("tools_used", [])
    total     = data.get("total_steps", "?")

    # Tools used chips
    if tools:
        chips = "  ".join(f"[cyan]🔧 {t}[/cyan]" for t in tools)
        console.print(f"\n[dim]Tools used:[/dim]  {chips}  [dim]· {total} steps[/dim]")

    console.print()
    console.print(Panel(
        Text(answer, style="white"),
        title="[bold green]✅  FINAL ANSWER[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))


# ── CLI group ────────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.option("--base",  default=DEFAULT_BASE,  envvar="IR_AGENT_URL",   help="Base URL")
@click.option("--token", default=DEFAULT_TOKEN, envvar="MY_API_TOKEN",   help="Bearer token")
@click.pass_context
def cli(ctx: click.Context, base: str, token: str) -> None:
    """🛡️  IR-Agent CLI — AI-powered Incident Response"""
    ctx.ensure_object(dict)
    ctx.obj["base"]  = base
    ctx.obj["token"] = token
    if ctx.invoked_subcommand is None:
        # No subcommand → launch shell
        ctx.invoke(shell)


# ═══════════════════════════════════════════════════════════════════════════
#  STATUS
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show server health and component status."""
    base, token = ctx.obj["base"], ctx.obj["token"]
    with make_client(base, token) as c:
        try:
            r = c.get("/health")
            d = r.json()
        except Exception as e:
            console.print(f"[bold red]❌  Cannot reach server:[/bold red] {e}")
            sys.exit(1)

    env   = d.get("environment", "?")
    ver   = d.get("version",     "?")
    comps = d.get("components",  {})
    cfg   = d.get("config",      {})

    t = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    t.add_column("Key",   style="dim", width=22)
    t.add_column("Value", style="white")

    t.add_row("🌐  Server",      f"[bold cyan]{base}[/bold cyan]")
    t.add_row("🟢  Status",      "[bold green]ONLINE[/bold green]")
    t.add_row("📦  Version",     ver)
    t.add_row("🏗  Environment", env)
    t.add_row("🤖  AI Analyzer", "[green]enabled[/green]" if comps.get("ai_analyzer") == "enabled" else "[red]disabled[/red]")
    t.add_row("📡  Better Stack","[green]enabled[/green]" if comps.get("better_stack") == "enabled" else "[dim]disabled[/dim]")
    t.add_row("🧠  AI Model",    cfg.get("ai_model", "?"))
    t.add_row("🔒  Threshold",   str(cfg.get("ai_threshold", "?")))

    console.print()
    console.print(Panel(t, title="[bold cyan]IR-Agent Status[/bold cyan]", border_style="cyan"))
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  QUERY (streaming)
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.argument("query_text")
@click.option("--session", "-s", default=None, help="Session ID (auto-generated if omitted)")
@click.option("--sync",    is_flag=True,        help="Use sync endpoint instead of streaming")
@click.pass_context
def query(ctx: click.Context, query_text: str, session: Optional[str], sync: bool) -> None:
    """Send a query to the CyberAgent (streaming by default)."""
    _run_query(ctx.obj["base"], ctx.obj["token"], query_text, session, sync)


def _run_query(base: str, token: str, query_text: str, session: Optional[str], sync: bool = False) -> None:
    sid = session or f"cli-{uuid.uuid4().hex[:8]}"
    payload = {"query": query_text, "session_id": sid}

    console.print()
    console.print(Rule(f"[dim]session: {sid}[/dim]", style="dim"))
    console.print(Panel(
        f"[bold white]{query_text}[/bold white]",
        title="[cyan]📥 Query[/cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    if sync:
        _query_sync(base, token, payload)
    else:
        _query_stream(base, token, payload)


def _query_stream(base: str, token: str, payload: dict) -> None:
    url = f"{base}/agent/query/stream"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    with console.status("[cyan]🤖 CyberAgent thinking…[/cyan]", spinner="dots"):
        try:
            with httpx.stream("POST", url, json=payload, headers=headers, timeout=TIMEOUT) as r:
                buf   = ""
                shown = False
                for chunk in r.iter_text():
                    buf += chunk
                    lines = buf.split("\n")
                    buf = lines.pop()
                    for ln in lines:
                        ln = ln.strip()
                        if not ln:
                            continue
                        try:
                            evt = json.loads(ln)
                        except json.JSONDecodeError:
                            continue
                        if evt.get("type") == "step" or (evt.get("action") is not None and evt.get("type") != "answer"):
                            if not shown:
                                console.print()  # push past spinner
                                shown = True
                            render_step(evt, console)
                        elif evt.get("type") == "answer" or evt.get("answer"):
                            render_answer(evt, console)
                # flush leftover
                if buf.strip():
                    try:
                        evt = json.loads(buf.strip())
                        if evt.get("answer"):
                            render_answer(evt, console)
                    except Exception:
                        pass
        except httpx.RequestError as e:
            console.print(f"[red]Connection error: {e}[/red]")


def _query_sync(base: str, token: str, payload: dict) -> None:
    with make_client(base, token) as c:
        with console.status("[cyan]🤖 Agent processing…[/cyan]", spinner="dots"):
            r = c.post("/agent/query", json=payload)
        d = r.json()
    for step in d.get("steps", []):
        if step.get("action") or step.get("thought"):
            render_step(step, console)
    if d.get("answer"):
        render_answer(d, console)


# ═══════════════════════════════════════════════════════════════════════════
#  TOOLS
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.pass_context
def tools(ctx: click.Context) -> None:
    """List all 9 agent tools with descriptions."""
    base, token = ctx.obj["base"], ctx.obj["token"]
    with make_client(base, token) as c:
        with console.status("[cyan]Loading tools…[/cyan]", spinner="dots"):
            r = c.get("/agent/tools")
        data = r.json()

    tool_list = data.get("tools", data) if isinstance(data, dict) else data

    ICONS = {
        "knowledge_search": "📚", "search_logs":    "🔍",
        "classify_event":   "🤖", "analyze_event":  "🧠",
        "mitre_lookup":     "🗺️", "lookup_ioc":     "🌐",
        "query_siem":       "📡", "investigate":    "🔬",
        "ml_classify":      "⚙️",
    }
    TYPES = {
        "knowledge_search": "RAG · FAISS",   "search_logs":   "Event Store",
        "classify_event":   "ML · Fast",      "analyze_event": "LLM · Groq",
        "mitre_lookup":     "Knowledge DB",   "lookup_ioc":    "Threat Intel",
        "query_siem":       "Better Stack",   "investigate":   "Full Pipeline",
        "ml_classify":      "ML + CyberML",
    }

    t = Table(
        title=f"[bold cyan]🔧 Tool Registry — {len(tool_list)} tools[/bold cyan]",
        box=box.ROUNDED, border_style="cyan", show_lines=True,
    )
    t.add_column("Tool",        style="bold cyan",  width=20)
    t.add_column("Type",        style="dim",        width=16)
    t.add_column("Description", style="white",      width=55)
    t.add_column("Parameters",  style="yellow",     width=20)

    for tool in tool_list:
        name  = tool.get("name", "?")
        desc  = (tool.get("description") or "")[:100]
        if len(tool.get("description", "")) > 100:
            desc += "…"
        raw_params = tool.get("parameters") or {}
        if isinstance(raw_params, str):
            try:
                raw_params = json.loads(raw_params)
            except Exception:
                raw_params = {}
        props = list(raw_params.get("properties", {}).keys())
        params_str = ", ".join(props[:3]) + ("..." if len(props) > 3 else "")
        t.add_row(
            f"{ICONS.get(name,'🔧')} {name}",
            TYPES.get(name, "Tool"),
            desc,
            params_str or "—",
        )

    console.print()
    console.print(t)
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  METRICS
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.option("--watch", "-w", is_flag=True, help="Refresh every 5 seconds (Ctrl+C to stop)")
@click.pass_context
def metrics(ctx: click.Context, watch: bool) -> None:
    """Show live processing metrics and ML model info."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    def _fetch_and_render() -> None:
        with make_client(base, token) as c:
            r1 = c.get("/ingest/metrics")
            r2 = c.get("/ingest/ml/status")
        m  = r1.json()
        ml = r2.json()

        proc  = m.get("processing", {})
        paths = m.get("paths", {})
        bs    = m.get("betterstack", {})
        model = ml.get("model", {})
        mlm   = model.get("metrics", {})

        # ── Processing cards ──
        cards = [
            Panel(f"[bold white]{proc.get('total_processed', 0)}[/bold white]\n[dim]Events total[/dim]",    border_style="cyan"),
            Panel(f"[bold red]{proc.get('malicious_detected', 0)}[/bold red]\n[dim]Threats found[/dim]",   border_style="red"),
            Panel(f"[bold green]{paths.get('fast_path_count', 0)}[/bold green]\n[dim]Fast-path[/dim]",     border_style="green"),
            Panel(f"[bold yellow]{paths.get('deep_path_count', 0)}[/bold yellow]\n[dim]Deep-path[/dim]",   border_style="yellow"),
        ]
        console.print(Columns(cards, equal=True, expand=True))

        # ── ML Model table ──
        ml_t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        ml_t.add_column("k", style="dim",   width=18)
        ml_t.add_column("v", style="white", width=22)
        ml_t.add_row("Type",     model.get("model_version", "GradientBoosting"))
        ml_t.add_row("Accuracy", f"[green]{mlm.get('accuracy', 0)*100:.2f}%[/green]" if mlm.get("accuracy") else "—")
        ml_t.add_row("ROC-AUC",  f"[green]{mlm.get('roc_auc', 0):.4f}[/green]"       if mlm.get("roc_auc") else "—")
        ml_t.add_row("F1",       f"[green]{mlm.get('f1', 0):.4f}[/green]"            if mlm.get("f1") else "—")
        ml_t.add_row("FPR",      f"{mlm.get('fpr', 0)*100:.1f}%"                     if mlm.get("fpr") is not None else "—")
        ml_t.add_row("FNR",      f"{mlm.get('fnr', 0)*100:.1f}%"                     if mlm.get("fnr") is not None else "—")
        ml_t.add_row("Features", str(model.get("n_features", "?")))
        ml_t.add_row("Samples",  f"{mlm.get('train_n', 0):,}"                        if mlm.get("train_n") else "—")
        ml_t.add_row("Threshold",str(model.get("threshold", "?")))

        # ── Agent info table ──
        ag_t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        ag_t.add_column("k", style="dim",   width=18)
        ag_t.add_column("v", style="white", width=22)
        ag_t.add_row("LLM",        "[green]Groq[/green]")
        ag_t.add_row("Model",      "llama-3.3-70b")
        ag_t.add_row("Max steps",  "8")
        ag_t.add_row("Timeout",    "120s")
        ag_t.add_row("Tools",      "[green]9[/green]")
        ag_t.add_row("Vectors",    "[green]33[/green]")
        ag_t.add_row("FAISS",      "[green]AVX2 · dim=384[/green]")
        ag_t.add_row("Better Stack","[green]enabled[/green]" if bs.get("enabled") else "[dim]disabled[/dim]")

        console.print(Columns([
            Panel(ml_t, title="[green]⚙️  ML Model — decoupled_v4[/green]", border_style="green"),
            Panel(ag_t, title="[cyan]🧠  CyberAgent[/cyan]",                 border_style="cyan"),
        ], equal=True, expand=True))

        ts = time.strftime("%H:%M:%S")
        console.print(f"[dim]  ↻ updated {ts}  ·  fast {paths.get('fast_path_rate','0%')}  "
                      f"·  deep {paths.get('deep_path_rate','0%')}  "
                      f"·  filtered {proc.get('filter_rate','0%')}[/dim]")

    if watch:
        try:
            while True:
                console.clear()
                console.print(f"\n[bold cyan]📊 IR-Agent — Live Metrics[/bold cyan]  [dim](Ctrl+C to exit)[/dim]\n")
                _fetch_and_render()
                time.sleep(5)
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/dim]")
    else:
        console.print(f"\n[bold cyan]📊 Metrics[/bold cyan]\n")
        _fetch_and_render()
        console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  IOC
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.argument("indicator")
@click.pass_context
def ioc(ctx: click.Context, indicator: str) -> None:
    """Quick IoC lookup (IP, domain, hash, URL)."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    query_text = f"Check if this is a malicious indicator of compromise: {indicator}"
    sid = f"cli-ioc-{uuid.uuid4().hex[:6]}"
    payload = {"query": query_text, "session_id": sid}

    console.print(f"\n[bold cyan]🌐 IoC Lookup:[/bold cyan]  [white]{indicator}[/white]\n")

    url     = f"{base}/agent/query/stream"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    with httpx.stream("POST", url, json=payload, headers=headers, timeout=TIMEOUT) as r:
        buf = ""
        for chunk in r.iter_text():
            buf += chunk
        lines = (buf + "\n").split("\n")
        events = []
        for ln in lines:
            ln = ln.strip()
            if ln:
                try:
                    events.append(json.loads(ln))
                except Exception:
                    pass

    # Show only observation from lookup_ioc step + final answer
    for evt in events:
        if evt.get("action") == "lookup_ioc":
            obs = evt.get("observation", "")
            verdict = "MALICIOUS" if "MALICIOUS" in str(obs).upper() else \
                      "SUSPICIOUS" if "SUSPICIOUS" in str(obs).upper() else "CLEAN"
            color = sev_color(verdict.lower())
            icon  = verdict_icon(verdict)
            console.print(Panel(
                Text(str(obs), style=color),
                title=f"[{color}]{icon}  {verdict}[/{color}]",
                border_style=color.split()[-1],
                padding=(0, 2),
            ))
        elif evt.get("answer"):
            console.print(Panel(
                Text(evt["answer"], style="white"),
                title="[bold green]✅  Analysis[/bold green]",
                border_style="green",
                padding=(1, 2),
            ))

    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  MITRE
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.argument("technique")
@click.pass_context
def mitre(ctx: click.Context, technique: str) -> None:
    """Look up a MITRE ATT&CK technique (e.g. T1003 or 'credential dumping')."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    query_text = f"Look up MITRE ATT&CK technique {technique} and explain what it does, what detection methods exist, and what mitigations apply."
    sid = f"cli-mitre-{uuid.uuid4().hex[:6]}"
    payload = {"query": query_text, "session_id": sid}

    console.print(f"\n[bold yellow]🗺️  MITRE Lookup:[/bold yellow]  [white]{technique}[/white]\n")

    url     = f"{base}/agent/query/stream"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    with httpx.stream("POST", url, json=payload, headers=headers, timeout=TIMEOUT) as r:
        buf = ""
        for chunk in r.iter_text():
            buf += chunk

    lines = (buf + "\n").split("\n")
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            evt = json.loads(ln)
        except Exception:
            continue
        if evt.get("action") == "mitre_lookup" and evt.get("observation"):
            console.print(Panel(
                Text(str(evt["observation"])[:600], style="yellow"),
                title="[yellow]📋  MITRE ATT&CK Entry[/yellow]",
                border_style="yellow",
                padding=(0, 2),
            ))
        elif evt.get("answer"):
            console.print(Panel(
                Text(evt["answer"], style="white"),
                title="[bold green]✅  Explanation[/bold green]",
                border_style="green",
                padding=(1, 2),
            ))

    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  INVESTIGATE
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.argument("incident_id")
@click.pass_context
def investigate(ctx: click.Context, incident_id: str) -> None:
    """Fetch and display an existing investigation report."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    console.print(f"\n[bold red]🔬 Investigation Report:[/bold red]  [white]{incident_id}[/white]\n")

    with make_client(base, token) as c:
        with console.status(f"[cyan]Fetching report for {incident_id}…[/cyan]", spinner="dots"):
            r = c.get(f"/investigation/{incident_id}/report")

    if r.status_code == 404:
        console.print(f"[red]Investigation '{incident_id}' not found.[/red]")
        # Show list
        with make_client(base, token) as c:
            lst = c.get("/investigation/list").json()
        inv_ids = lst.get("investigations", [])
        if inv_ids:
            console.print(f"[dim]Available:[/dim] {', '.join(inv_ids)}")
        return

    data   = r.json()
    report = data.get("report", "No report available.")

    # Pretty-print sections
    in_section = False
    section_buf: list[str] = []

    def _flush(buf: list[str], title: str) -> None:
        txt = "\n".join(buf).strip()
        if txt:
            console.print(Panel(
                Text(txt, style="white"),
                title=f"[bold cyan]{title}[/bold cyan]",
                border_style="dim",
                padding=(0, 2),
            ))

    SECTION_MARKS = {
        "EXECUTIVE SUMMARY":       "📋  Executive Summary",
        "ATTACK TIMELINE":         "⏱️   Attack Timeline",
        "INDICATORS OF COMPROMISE":"🔴  IoCs",
        "TTP ANALYSIS":            "🗺️   MITRE TTPs",
        "ROOT CAUSE ANALYSIS":     "🔍  Root Cause",
        "IMPACT ASSESSMENT":       "💥  Impact",
        "CONTAINMENT ACTIONS":     "🛡️   Containment",
        "REMEDIATION STEPS":       "🔧  Remediation",
        "LESSONS LEARNED":         "📚  Lessons Learned",
    }

    current_title = ""
    buf: list[str] = []

    for line in report.splitlines():
        stripped = line.strip()
        # Section header detection (surrounded by ===)
        found_section = None
        for marker, label in SECTION_MARKS.items():
            if marker in stripped:
                found_section = label
                break
        if stripped.startswith("====") or stripped.startswith("----"):
            continue
        if found_section:
            if buf and current_title:
                _flush(buf, current_title)
            current_title = found_section
            buf = []
        elif stripped.startswith("CYBER INCIDENT INVESTIGATION REPORT"):
            console.print(Rule("[bold red]📄  CYBER INCIDENT INVESTIGATION REPORT[/bold red]", style="red"))
        elif stripped.startswith("Incident ID:") or stripped.startswith("Title:") \
                or stripped.startswith("Type:") or stripped.startswith("Investigation Date:"):
            console.print(f"[dim]  {stripped}[/dim]")
        else:
            buf.append(line)

    if buf and current_title:
        _flush(buf, current_title)

    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  ASSESS  — interactive 4-signal ThreatAssessment
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.pass_context
def assess(ctx: click.Context) -> None:
    """Interactive 4-signal threat assessment (ML + IoC + MITRE + Agent)."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    console.print()
    console.print(Panel(
        "[dim]Введите данные сигналов. Enter = skip / оставить пустым.[/dim]",
        title="[bold orange1]⚖️  Threat Assessment Engine[/bold orange1]",
        border_style="orange1",
    ))

    def _float_prompt(msg: str, default: str = "") -> Optional[float]:
        val = Prompt.ask(f"  [dim]{msg}[/dim]", default=default)
        try:
            return float(val) if val else None
        except ValueError:
            return None

    def _bool_prompt(msg: str) -> bool:
        return Confirm.ask(f"  [dim]{msg}[/dim]", default=False)

    payload: dict = {}

    # ML signal
    console.print("\n[cyan]── ML Signal ──[/cyan]")
    ml_score = _float_prompt("ML score (0.0–1.0)", "")
    if ml_score is not None:
        payload["ml"] = {
            "score":        ml_score,
            "is_malicious": ml_score >= 0.5,
            "reason":       Prompt.ask("  [dim]Reason[/dim]", default="ML detection"),
            "model_loaded": True,
        }

    # IoC signal
    console.print("\n[green]── IoC Signal ──[/green]")
    ioc_score = _float_prompt("IoC score (0.0–1.0)", "")
    if ioc_score is not None:
        payload["ioc"] = {
            "score":           ioc_score,
            "is_malicious":    ioc_score >= 0.5,
            "providers_hit":   [p.strip() for p in Prompt.ask("  [dim]Providers (comma-sep)[/dim]", default="Local ThreatDB").split(",")],
            "indicator_count": int(_float_prompt("IoC count", "1") or 1),
        }

    # MITRE signal
    console.print("\n[yellow]── MITRE Signal ──[/yellow]")
    tech_ids = Prompt.ask("  [dim]Technique IDs (comma-sep, e.g. T1003,T1055)[/dim]", default="")
    if tech_ids.strip():
        techs = [{"id": t.strip(), "name": t.strip(), "confidence": 0.85} for t in tech_ids.split(",") if t.strip()]
        payload["mitre"] = {
            "techniques":          techs,
            "tactic_coverage":     [Prompt.ask("  [dim]Tactic coverage (comma-sep)[/dim]", default="execution")],
            "max_confidence":      float(_float_prompt("Max confidence", "0.85") or 0.85),
            "has_lateral_movement":_bool_prompt("Lateral movement?"),
            "has_credential_access":_bool_prompt("Credential access?"),
            "has_impact":          _bool_prompt("Impact tactic?"),
        }

    # Agent signal
    console.print("\n[purple]── Agent Signal ──[/purple]")
    agent_ver = Prompt.ask("  [dim]Verdict (MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN)[/dim]", default="")
    if agent_ver.strip():
        payload["agent"] = {
            "verdict":         agent_ver.upper(),
            "confidence":      float(_float_prompt("Confidence", "0.9") or 0.9),
            "tools_used":      [t.strip() for t in Prompt.ask("  [dim]Tools used[/dim]", default="lookup_ioc").split(",")],
            "reasoning_steps": int(_float_prompt("Steps taken", "2") or 2),
        }

    if not any(payload.get(k) for k in ["ml", "ioc", "mitre", "agent"]):
        console.print("[red]No signals provided. Exiting.[/red]")
        return

    console.print()
    with make_client(base, token) as c:
        with console.status("[cyan]Running assessment…[/cyan]", spinner="dots"):
            r = c.post("/assessment/analyze", json=payload)
    d = r.json()

    sev   = d.get("severity", "?")
    score = d.get("final_score", "?")
    conf  = d.get("confidence_level", "?")
    color = sev_color(sev)

    # Score panel
    score_txt = Text()
    score_txt.append(f"\n  Score:      ", style="dim")
    score_txt.append(f"{score}/100\n", style=f"bold {color}")
    score_txt.append(f"  Severity:   ", style="dim")
    score_txt.append(f"{sev.upper()}\n", style=f"bold {color}")
    score_txt.append(f"  Confidence: ", style="dim")
    score_txt.append(f"{conf}\n", style="white")
    score_txt.append(f"  Action:     ", style="dim")
    score_txt.append(d.get("recommended_action", ""), style="bold white")

    console.print(Panel(
        score_txt,
        title=f"[{color}]⚖️  Assessment Result — {sev.upper()}[/{color}]",
        border_style=color.split()[-1],
        padding=(0, 1),
    ))

    # Breakdown table
    breakdown = d.get("score_breakdown", {})
    if breakdown:
        bt = Table(box=box.SIMPLE, show_header=True, padding=(0, 3))
        bt.add_column("Signal", style="dim")
        bt.add_column("Weight contribution", style="cyan", justify="right")
        for sig, val in breakdown.items():
            bt.add_row(sig.upper(), f"{val:.1f} pts")
        console.print(bt)

    # Explanation trace
    trace = d.get("explanation_trace", [])
    if trace:
        console.print(Panel(
            "\n".join(f"[dim]  {i+1}.[/dim] {line}" for i, line in enumerate(trace)),
            title="[dim]📋  Explanation Trace[/dim]",
            border_style="dim",
            padding=(0, 1),
        ))

    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  SHELL — interactive REPL
# ═══════════════════════════════════════════════════════════════════════════
@cli.command()
@click.pass_context
def shell(ctx: click.Context) -> None:
    """Interactive REPL — type queries directly to the CyberAgent."""
    base, token = ctx.obj["base"], ctx.obj["token"]

    # Verify server
    try:
        with make_client(base, token) as c:
            h = c.get("/health").json()
        env  = h.get("environment", "?")
        ver  = h.get("version", "?")
        status_line = f"[green]● ONLINE[/green]  {ver}  [{env}]  {base}"
    except Exception:
        status_line = f"[red]● OFFLINE[/red]  {base}"

    console.print(BANNER)
    console.print(Panel(
        status_line,
        title="[bold cyan]Connection[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    HELP = """[bold cyan]Commands:[/bold cyan]
  [white]<any text>[/white]          → [dim]send query to CyberAgent (streaming)[/dim]
  [white]/ioc <indicator>[/white]    → [dim]quick IoC lookup[/dim]
  [white]/mitre <T1003>[/white]      → [dim]MITRE technique info[/dim]
  [white]/tools[/white]              → [dim]list all tools[/dim]
  [white]/metrics[/white]            → [dim]show metrics[/dim]
  [white]/status[/white]             → [dim]server status[/dim]
  [white]/assess[/white]             → [dim]interactive threat assessment[/dim]
  [white]/investigate <id>[/white]   → [dim]fetch investigation report[/dim]
  [white]/clear[/white]              → [dim]clear screen[/dim]
  [white]/help[/white]               → [dim]show this help[/dim]
  [white]/exit[/white]  or  Ctrl+C   → [dim]quit[/dim]"""

    console.print(Panel(HELP, title="[dim]Help[/dim]", border_style="dim", padding=(0, 2)))
    console.print()

    sid = f"shell-{uuid.uuid4().hex[:8]}"
    console.print(f"[dim]Session: {sid}[/dim]\n")

    while True:
        try:
            raw = Prompt.ask("[bold cyan]ir-agent[/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        raw = raw.strip()
        if not raw:
            continue

        if raw in ("/exit", "/quit", "exit", "quit"):
            console.print("[dim]Goodbye.[/dim]")
            break
        elif raw == "/clear":
            console.clear()
        elif raw == "/help":
            console.print(Panel(HELP, border_style="dim", padding=(0, 2)))
        elif raw == "/tools":
            ctx.invoke(tools)
        elif raw == "/metrics":
            ctx.invoke(metrics)
        elif raw == "/status":
            ctx.invoke(status)
        elif raw == "/assess":
            ctx.invoke(assess)
        elif raw.startswith("/ioc "):
            indicator = raw[5:].strip()
            ctx.invoke(ioc, indicator=indicator)
        elif raw.startswith("/mitre "):
            tech = raw[7:].strip()
            ctx.invoke(mitre, technique=tech)
        elif raw.startswith("/investigate "):
            inc_id = raw[13:].strip()
            ctx.invoke(investigate, incident_id=inc_id)
        else:
            # Regular agent query
            _run_query(base, token, raw, sid, sync=False)
            console.print()


# ── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cli(obj={})
