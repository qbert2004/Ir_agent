#!/usr/bin/env python3
"""
IR-Agent TUI  -  Full-screen Terminal User Interface
-----------------------------------------------------
Usage:  python tui.py

Tabs  (switch with keys 1-8 or mouse):
  1  Status       - server health
  2  Query        - streaming ReAct agent
  3  Tools        - tool registry
  4  Metrics      - live ML + event stats
  5  IoC          - indicator lookup
  6  MITRE        - ATT&CK technique search
  7  Investigate  - investigation report viewer
  8  Assess       - 4-signal threat assessment

Note: HTTP calls run in thread workers (sync httpx) to avoid
      anyio/asyncio incompatibilities on Python 3.14.
"""
from __future__ import annotations

import json
import os
import uuid
from typing import Optional

import httpx
from dotenv import load_dotenv
from rich.rule  import Rule
from rich.table import Table as RichTable
from rich.text  import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    TabbedContent,
    TabPane,
)

load_dotenv()

BASE    = os.getenv("IR_AGENT_URL", "http://localhost:9000")
TOKEN   = os.getenv("MY_API_TOKEN", "WAhV9fBn2sRyuOXLv6MNlwT4gHFbYKPS")
TIMEOUT = 120.0


def _hdrs() -> dict:
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def _client(timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=timeout,
    )


def sev_style(s: str) -> str:
    return {
        "critical":   "bold red",
        "high":       "red",
        "medium":     "yellow",
        "low":        "green",
        "info":       "cyan",
        "clean":      "green",
        "malicious":  "bold red",
        "suspicious": "yellow",
    }.get(str(s).lower(), "white")


# ── CSS ────────────────────────────────────────────────────────────────────────
APP_CSS = """
Screen        { background: #0d1117; }
TabbedContent { height: 1fr; }
TabPane       { padding: 1 2; }

RichLog {
    border:          round #1c3a5a;
    background:      #070b10;
    scrollbar-color: #1c3a5a;
}

/* Status */
#status-log  { height: 1fr; }

/* Query */
#query-input { margin-bottom: 1; }
#query-log   { height: 1fr; }

/* Tools */
#tools-table { height: 1fr; }

/* Metrics */
#metrics-log { height: 1fr; }

/* IoC / MITRE */
#ioc-input, #mitre-input  { margin-bottom: 1; }
#ioc-log, #mitre-log      { height: 1fr; }

/* Incidents */
#invest-buttons { height: 3; margin-bottom: 1; }
#invest-input   { margin-bottom: 1; }
#invest-log     { height: 1fr; }

/* Assess */
.assess-row { height: 3; margin-bottom: 1; }
.assess-lbl { width: 22; padding-top: 1; color: $text-muted; }
#assess-btn { margin-bottom: 1; width: 22; }
#assess-log { height: 1fr; }
"""


# ══════════════════════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════════════════════
class IrAgentTUI(App):
    """IR-Agent TUI."""

    TITLE    = "IR-Agent  |  AI Incident Response"
    CSS      = APP_CSS
    BINDINGS = [
        Binding("q",      "quit",                   "Quit"),
        Binding("r",      "refresh",                "Refresh"),
        Binding("ctrl+c", "quit",                   "Quit",       show=False),
        Binding("1",      "switch_tab('status')",   "Status",     show=False),
        Binding("2",      "switch_tab('query')",    "Query",      show=False),
        Binding("3",      "switch_tab('tools')",    "Tools",      show=False),
        Binding("4",      "switch_tab('metrics')",  "Metrics",    show=False),
        Binding("5",      "switch_tab('ioc')",      "IoC",        show=False),
        Binding("6",      "switch_tab('mitre')",    "MITRE",      show=False),
        Binding("7",      "switch_tab('invest')",   "Investigate",show=False),
        Binding("8",      "switch_tab('assess')",   "Assess",     show=False),
    ]

    # ── Compose ──────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent(initial="status"):

            with TabPane("Status [1]", id="status"):
                yield RichLog(id="status-log", highlight=True, markup=True)

            with TabPane("Query [2]", id="query"):
                yield Input(
                    placeholder="Ask the CyberAgent...  (Enter to send)",
                    id="query-input",
                )
                yield RichLog(id="query-log", highlight=True, markup=True)

            with TabPane("Tools [3]", id="tools"):
                yield DataTable(
                    id="tools-table", cursor_type="row", zebra_stripes=True
                )

            with TabPane("Metrics [4]", id="metrics"):
                yield RichLog(id="metrics-log", highlight=True, markup=True)

            with TabPane("IoC [5]", id="ioc"):
                yield Input(
                    placeholder="IP, domain, file hash or URL...  (Enter to lookup)",
                    id="ioc-input",
                )
                yield RichLog(id="ioc-log", highlight=True, markup=True)

            with TabPane("MITRE [6]", id="mitre"):
                yield Input(
                    placeholder="Technique ID or keyword  (T1003, credential dumping)...",
                    id="mitre-input",
                )
                yield RichLog(id="mitre-log", highlight=True, markup=True)

            with TabPane("Incidents [7]", id="invest"):
                with Horizontal(id="invest-buttons"):
                    yield Button("List All", id="list-incidents-btn", variant="default")
                    yield Button("Investigate", id="do-investigate-btn", variant="warning")
                yield Input(
                    placeholder="Incident ID (IR-20260427-XXXXXX)...  Enter to view report",
                    id="invest-input",
                )
                yield RichLog(id="invest-log", highlight=True, markup=True)

            with TabPane("Assess [8]", id="assess"):
                with Horizontal(classes="assess-row"):
                    yield Label("ML score (0-1):",    classes="assess-lbl")
                    yield Input(placeholder="0.87",   id="ml-score")
                with Horizontal(classes="assess-row"):
                    yield Label("IoC score (0-1):",   classes="assess-lbl")
                    yield Input(placeholder="0.60",   id="ioc-score")
                with Horizontal(classes="assess-row"):
                    yield Label("Techniques:",         classes="assess-lbl")
                    yield Input(placeholder="T1003,T1055,T1059", id="tech-ids")
                with Horizontal(classes="assess-row"):
                    yield Label("Agent verdict:",      classes="assess-lbl")
                    yield Input(
                        placeholder="MALICIOUS / SUSPICIOUS / CLEAN",
                        id="agent-verdict",
                    )
                yield Button("Run Assessment", id="assess-btn", variant="primary")
                yield RichLog(id="assess-log", highlight=True, markup=True)

        yield Footer()

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        self._load_status()
        self._load_tools()
        self._load_metrics()
        self.set_interval(15, self._load_metrics)

    # ── Tab switching ────────────────────────────────────────────────────────
    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_refresh(self) -> None:
        active = self.query_one(TabbedContent).active
        if   active == "status":  self._load_status()
        elif active == "metrics": self._load_metrics()
        elif active == "tools":   self._load_tools()

    # ── Thread-safe helpers ──────────────────────────────────────────────────
    def _log_clear(self, log_id: str) -> None:
        self.call_from_thread(self.query_one(log_id, RichLog).clear)

    def _log_write(self, log_id: str, content) -> None:
        self.call_from_thread(self.query_one(log_id, RichLog).write, content)

    # ════════════════════════════════════════════════════════════════════════
    #  STATUS
    # ════════════════════════════════════════════════════════════════════════
    @work(thread=True, exclusive=True)
    def _load_status(self) -> None:
        lid = "#status-log"
        self._log_clear(lid)
        self._log_write(lid, "[dim]Connecting to server...[/dim]")
        try:
            with _client() as c:
                d = c.get(f"{BASE}/health").json()
        except Exception as e:
            self._log_clear(lid)
            self._log_write(lid, f"[bold red]Cannot reach {BASE}[/bold red]\n{e}")
            return

        comps = d.get("components", {})
        cfg   = d.get("config", {})

        self._log_clear(lid)
        self._log_write(lid, Rule("[bold cyan]Server Health[/bold cyan]"))

        t = RichTable(box=None, show_header=False, padding=(0, 3))
        t.add_column("Key",   style="dim",   min_width=18)
        t.add_column("Value", style="white", min_width=30)
        t.add_row("Server",       f"[bold cyan]{BASE}[/bold cyan]")
        t.add_row("Status",       "[bold green]ONLINE[/bold green]")
        t.add_row("Version",      d.get("version", "?"))
        t.add_row("Environment",  d.get("environment", "?"))
        t.add_row("AI Analyzer",  "[green]enabled[/green]"
                  if comps.get("ai_analyzer") == "enabled" else "[red]disabled[/red]")
        t.add_row("Better Stack", "[green]enabled[/green]"
                  if comps.get("better_stack") == "enabled" else "[dim]disabled[/dim]")
        t.add_row("AI Model",     cfg.get("ai_model", "?"))
        t.add_row("Threshold",    str(cfg.get("ai_threshold", "?")))
        self._log_write(lid, t)

        self._log_write(lid, Rule("[bold cyan]Agent Config[/bold cyan]"))
        t2 = RichTable(box=None, show_header=False, padding=(0, 3))
        t2.add_column("Key",   style="dim",   min_width=18)
        t2.add_column("Value", style="white", min_width=30)
        t2.add_row("LLM",       "[green]Groq / llama-3.3-70b[/green]")
        t2.add_row("FAISS",     "[green]AVX2  dim=384[/green]")
        t2.add_row("Tools",     "[green]11 registered[/green]")
        t2.add_row("Vectors",   "[green]33 knowledge entries[/green]")
        t2.add_row("Max steps", "8")
        self._log_write(lid, t2)

    # ════════════════════════════════════════════════════════════════════════
    #  TOOLS
    # ════════════════════════════════════════════════════════════════════════
    @work(thread=True, exclusive=True)
    def _load_tools(self) -> None:
        try:
            with _client() as c:
                data = c.get(f"{BASE}/agent/tools").json()
        except Exception:
            return

        tools = data.get("tools", data) if isinstance(data, dict) else data
        TYPES = {
            "knowledge_search":    "RAG / FAISS",
            "search_logs":         "Event Store",
            "classify_event":      "ML  Fast",
            "analyze_event":       "LLM / Groq",
            "mitre_lookup":        "Knowledge DB",
            "lookup_ioc":          "Threat Intel",
            "query_siem":          "Better Stack",
            "investigate":         "Full Pipeline",
            "ml_classify":         "ML + CyberML",
            "get_incident":        "Incident Manager",
            "get_incident_events": "Incident Manager",
        }

        dt = self.query_one("#tools-table", DataTable)

        def _fill() -> None:
            dt.clear(columns=True)
            dt.add_columns("#", "Tool", "Type", "Description")
            for i, tool in enumerate(tools, 1):
                name = tool.get("name", "?")
                desc = (tool.get("description") or "")[:90]
                dt.add_row(str(i), name, TYPES.get(name, "Tool"), desc)

        self.call_from_thread(_fill)

    # ════════════════════════════════════════════════════════════════════════
    #  METRICS
    # ════════════════════════════════════════════════════════════════════════
    @work(thread=True, exclusive=True)
    def _load_metrics(self) -> None:
        lid = "#metrics-log"
        self._log_clear(lid)
        self._log_write(lid, "[dim]Loading metrics...[/dim]")
        try:
            with _client() as c:
                m  = c.get(f"{BASE}/ingest/metrics").json()
                ml = c.get(f"{BASE}/ingest/ml/status").json()
        except Exception as e:
            self._log_clear(lid)
            self._log_write(lid, f"[red]Error: {e}[/red]")
            return

        proc  = m.get("processing", {})
        paths = m.get("paths", {})
        model = ml.get("model", {})
        mlm   = model.get("metrics", {})

        self._log_clear(lid)
        self._log_write(lid, Rule("[cyan]Event Processing[/cyan]"))

        t1 = RichTable(box=None, show_header=True, padding=(0, 3))
        t1.add_column("Metric",     style="dim",       min_width=20)
        t1.add_column("Value",      style="bold cyan", min_width=12)
        t1.add_row("Total events",  str(proc.get("total_processed",    0)))
        t1.add_row("Threats found", str(proc.get("malicious_detected", 0)))
        t1.add_row("Fast-path",     str(paths.get("fast_path_count",   0)))
        t1.add_row("Deep-path",     str(paths.get("deep_path_count",   0)))
        t1.add_row("Fast rate",            paths.get("fast_path_rate", "0%"))
        t1.add_row("Deep rate",            paths.get("deep_path_rate", "0%"))
        t1.add_row("Filter rate",          proc.get("filter_rate", "0%"))
        t1.add_row("Agent invocations",    str(paths.get("agent_invocations", 0)))
        t1.add_row("Background invest.",   str(paths.get("background_investigations", 0)))
        self._log_write(lid, t1)

        self._log_write(lid, Rule("[green]ML Model[/green]"))
        t2 = RichTable(box=None, show_header=False, padding=(0, 3))
        t2.add_column("k", style="dim",   min_width=18)
        t2.add_column("v", style="white", min_width=20)
        t2.add_row("Model type", model.get("model_version", "GradientBoosting"))
        if mlm.get("accuracy"):
            t2.add_row("Accuracy",  f"[green]{mlm['accuracy']*100:.2f}%[/green]")
        if mlm.get("roc_auc"):
            t2.add_row("ROC-AUC",   f"[green]{mlm['roc_auc']:.4f}[/green]")
        if mlm.get("f1"):
            t2.add_row("F1 score",  f"[green]{mlm['f1']:.4f}[/green]")
        if mlm.get("fpr") is not None:
            t2.add_row("FPR",       f"{mlm['fpr']*100:.1f}%")
        if mlm.get("fnr") is not None:
            t2.add_row("FNR",       f"{mlm['fnr']*100:.1f}%")
        t2.add_row("Features",  str(model.get("n_features", "?")))
        if mlm.get("train_n"):
            t2.add_row("Train set", f"{mlm['train_n']:,}")
        t2.add_row("Threshold", str(model.get("threshold", "?")))
        self._log_write(lid, t2)

        self._log_write(lid, Rule("[blue]CyberAgent[/blue]"))
        t3 = RichTable(box=None, show_header=False, padding=(0, 3))
        t3.add_column("k", style="dim",   min_width=18)
        t3.add_column("v", style="white", min_width=20)
        t3.add_row("LLM",      "[green]Groq[/green]")
        t3.add_row("Model",    "llama-3.3-70b-versatile")
        t3.add_row("Max steps","8")
        t3.add_row("Tools",    "[green]9[/green]")
        t3.add_row("Vectors",  "[green]33[/green]")
        t3.add_row("FAISS",    "[green]AVX2  dim=384[/green]")
        self._log_write(lid, t3)

    # ════════════════════════════════════════════════════════════════════════
    #  QUERY  (streaming)
    # ════════════════════════════════════════════════════════════════════════
    @on(Input.Submitted, "#query-input")
    def _on_query_submit(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        log = self.query_one("#query-log", RichLog)
        log.write(Rule(f"[cyan]{text[:70]}[/cyan]"))
        self._stream_query(text, "#query-log")

    @work(thread=True)
    def _stream_query(self, query_text: str, log_id: str) -> None:
        sid     = f"tui-{uuid.uuid4().hex[:8]}"
        payload = {"query": query_text, "session_id": sid}
        self._log_write(log_id, "[dim]Agent thinking...[/dim]")
        try:
            with httpx.stream(
                "POST", f"{BASE}/agent/query/stream",
                json=payload, headers=_hdrs(), timeout=TIMEOUT,
            ) as resp:
                buf = ""
                for chunk in resp.iter_text():
                    buf += chunk
                    lines = buf.split("\n")
                    buf   = lines.pop()
                    for ln in lines:
                        ln = ln.strip()
                        if ln:
                            try:
                                self._dispatch_event(log_id, json.loads(ln))
                            except Exception:
                                pass
                if buf.strip():
                    try:
                        self._dispatch_event(log_id, json.loads(buf.strip()))
                    except Exception:
                        pass
        except Exception as e:
            self._log_write(log_id, f"[red]Connection error: {e}[/red]")

    def _dispatch_event(self, log_id: str, evt: dict) -> None:
        """Render one NDJSON streaming event into the target RichLog."""
        is_step = evt.get("type") == "step" or (
            evt.get("action") and evt.get("type") != "answer"
        )
        is_answer = evt.get("type") == "answer" or evt.get("answer")

        if is_step:
            hdr = Text()
            hdr.append(f" STEP {evt.get('step','?')} ", style="bold black on cyan")
            if evt.get("action"):
                hdr.append(f"  > {evt['action']}", style="bold cyan")
            self._log_write(log_id, hdr)
            if evt.get("thought"):
                self._log_write(
                    log_id,
                    Text(f"  {str(evt['thought'])[:260]}", style="dim italic"),
                )
            if evt.get("observation"):
                self._log_write(
                    log_id,
                    Text(f"  {str(evt['observation'])[:460]}", style="green"),
                )
        elif is_answer:
            tools = evt.get("tools_used", [])
            steps = evt.get("total_steps", "?")
            if tools:
                self._log_write(
                    log_id,
                    Text(f"Tools: {', '.join(tools)}  |  {steps} steps", style="dim"),
                )
            self._log_write(log_id, Rule("[bold green]FINAL ANSWER[/bold green]"))
            self._log_write(log_id, Text(evt.get("answer", ""), style="white"))

    # ════════════════════════════════════════════════════════════════════════
    #  IOC
    # ════════════════════════════════════════════════════════════════════════
    @on(Input.Submitted, "#ioc-input")
    def _on_ioc_submit(self, event: Input.Submitted) -> None:
        indicator = event.value.strip()
        if not indicator:
            return
        event.input.value = ""
        log = self.query_one("#ioc-log", RichLog)
        log.write(Rule(f"[cyan]{indicator}[/cyan]"))
        self._lookup_ioc(indicator)

    @work(thread=True)
    def _lookup_ioc(self, indicator: str) -> None:
        lid     = "#ioc-log"
        payload = {
            "query":      f"Check if this indicator is malicious: {indicator}",
            "session_id": f"tui-ioc-{uuid.uuid4().hex[:6]}",
        }
        self._log_write(lid, "[dim]Looking up...[/dim]")
        buf = ""
        try:
            with httpx.stream(
                "POST", f"{BASE}/agent/query/stream",
                json=payload, headers=_hdrs(), timeout=TIMEOUT,
            ) as resp:
                for chunk in resp.iter_text():
                    buf += chunk
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        for ln in (buf + "\n").split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                evt = json.loads(ln)
            except Exception:
                continue
            if evt.get("action") == "lookup_ioc" and evt.get("observation"):
                obs     = str(evt["observation"])
                verdict = ("MALICIOUS"  if "MALICIOUS"  in obs.upper() else
                           "SUSPICIOUS" if "SUSPICIOUS" in obs.upper() else "CLEAN")
                st = sev_style(verdict.lower())
                self._log_write(lid, Text(f"Verdict: {verdict}", style=f"bold {st}"))
                self._log_write(lid, Text(obs[:500], style=st))
            elif evt.get("answer"):
                self._log_write(lid, Rule("[green]Analysis[/green]"))
                self._log_write(lid, Text(evt["answer"], style="white"))

    # ════════════════════════════════════════════════════════════════════════
    #  MITRE
    # ════════════════════════════════════════════════════════════════════════
    @on(Input.Submitted, "#mitre-input")
    def _on_mitre_submit(self, event: Input.Submitted) -> None:
        tech = event.value.strip()
        if not tech:
            return
        event.input.value = ""
        log = self.query_one("#mitre-log", RichLog)
        log.write(Rule(f"[yellow]{tech}[/yellow]"))
        self._lookup_mitre(tech)

    @work(thread=True)
    def _lookup_mitre(self, technique: str) -> None:
        lid     = "#mitre-log"
        payload = {
            "query": (
                f"Look up MITRE ATT&CK technique {technique} — explain what it does, "
                "detection methods, and mitigations."
            ),
            "session_id": f"tui-mitre-{uuid.uuid4().hex[:6]}",
        }
        self._log_write(lid, "[dim]Searching ATT&CK database...[/dim]")
        buf = ""
        try:
            with httpx.stream(
                "POST", f"{BASE}/agent/query/stream",
                json=payload, headers=_hdrs(), timeout=TIMEOUT,
            ) as resp:
                for chunk in resp.iter_text():
                    buf += chunk
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        for ln in (buf + "\n").split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                evt = json.loads(ln)
            except Exception:
                continue
            if evt.get("action") == "mitre_lookup" and evt.get("observation"):
                self._log_write(lid, Rule("[yellow]ATT&CK Entry[/yellow]"))
                self._log_write(lid, Text(str(evt["observation"])[:600], style="yellow"))
            elif evt.get("answer"):
                self._log_write(lid, Rule("[green]Explanation[/green]"))
                self._log_write(lid, Text(evt["answer"], style="white"))

    # ════════════════════════════════════════════════════════════════════════
    #  INCIDENTS
    # ════════════════════════════════════════════════════════════════════════
    @on(Input.Submitted, "#invest-input")
    def _on_invest_submit(self, event: Input.Submitted) -> None:
        inc_id = event.value.strip()
        if not inc_id:
            return
        event.input.value = ""
        self.query_one("#invest-log", RichLog).write(Rule(f"[cyan]{inc_id}[/cyan]"))
        self._fetch_incident_report(inc_id)

    @on(Button.Pressed, "#list-incidents-btn")
    def _on_list_btn(self, _: Button.Pressed) -> None:
        self._list_incidents()

    @on(Button.Pressed, "#do-investigate-btn")
    def _on_do_investigate_btn(self, _: Button.Pressed) -> None:
        inc_id = self.query_one("#invest-input", Input).value.strip()
        if not inc_id:
            self._log_write("#invest-log", "[red]Enter an incident ID first.[/red]")
            return
        self.query_one("#invest-input", Input).value = ""
        self.query_one("#invest-log", RichLog).write(
            Rule(f"[yellow]Investigating {inc_id}...[/yellow]")
        )
        self._run_incident_investigation(inc_id)

    @work(thread=True)
    def _list_incidents(self) -> None:
        lid = "#invest-log"
        self._log_clear(lid)
        self._log_write(lid, "[dim]Loading incidents...[/dim]")
        try:
            with _client() as c:
                data = c.get(f"{BASE}/ingest/incidents").json()
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        incidents = data.get("incidents", [])
        stats     = data.get("stats", {})

        self._log_clear(lid)
        self._log_write(
            lid,
            Rule(
                f"[cyan]Incidents — total: {stats.get('total_incidents', len(incidents))}, "
                f"active: {stats.get('active_incidents', '?')}[/cyan]"
            ),
        )

        if not incidents:
            self._log_write(lid, "[dim]No incidents yet.[/dim]")
            return

        t = RichTable(box=None, show_header=True, padding=(0, 2))
        t.add_column("ID",             style="cyan",  min_width=22)
        t.add_column("Host",           style="white", min_width=14)
        t.add_column("Severity",       style="white", min_width=10)
        t.add_column("Events",         style="white", min_width=6)
        t.add_column("Status",         style="white", min_width=12)
        t.add_column("Classification", style="dim",   min_width=30)

        for inc in incidents:
            sev = inc.get("severity", "info")
            st  = sev_style(sev)
            t.add_row(
                inc.get("id", "?"),
                inc.get("host", "?"),
                Text(sev.upper(), style=f"bold {st}"),
                str(inc.get("event_count", 0)),
                inc.get("status", "?"),
                (inc.get("classification") or "")[:45],
            )

        self._log_write(lid, t)
        self._log_write(lid, Text(
            "\nTip: enter an incident ID and press Enter to view report, "
            "or press [Investigate] to run AI analysis.",
            style="dim",
        ))

    @work(thread=True)
    def _fetch_incident_report(self, incident_id: str) -> None:
        lid = "#invest-log"
        self._log_write(lid, "[dim]Fetching report...[/dim]")
        try:
            with _client(timeout=30) as c:
                r = c.get(f"{BASE}/ingest/incidents/{incident_id}/report")
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        if r.status_code != 200 or r.json().get("status") == "error":
            self._log_write(lid, f"[red]Incident '{incident_id}' not found.[/red]")
            self._list_incidents()
            return

        report = r.json().get("report", "")
        self._log_clear(lid)

        BOLD_SECTIONS = {
            "INCIDENT INVESTIGATION REPORT",
            "ATTACK TIMELINE", "INDICATORS OF COMPROMISE",
            "MITRE ATT&CK MAPPING", "ROOT CAUSE ANALYSIS",
            "IMPACT ASSESSMENT", "RECOMMENDED RESPONSE",
            "KEY FINDINGS", "AI AGENT INVESTIGATION", "INCIDENT SUMMARY",
        }
        for line in report.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("="):
                self._log_write(lid, Rule(style="dim cyan"))
            elif s.startswith("-"):
                self._log_write(lid, Rule(style="dim"))
            elif any(sec in s for sec in BOLD_SECTIONS):
                self._log_write(lid, Text(s, style="bold cyan"))
            elif s.startswith("Incident ID"):
                self._log_write(lid, Text(s, style="bold white"))
            elif s.startswith(("Severity:", "Confidence:", "Status:")):
                key, _, val = s.partition(":")
                sev_val = val.strip().lower().rstrip(".")
                st = sev_style(sev_val)
                txt = Text()
                txt.append(f"{key}:", style="dim")
                txt.append(f" {val.strip()}", style=f"bold {st}")
                self._log_write(lid, txt)
            elif s.startswith("Verdict:") or "MALICIOUS" in s or "SUSPICIOUS" in s:
                self._log_write(lid, Text(s, style=sev_style("malicious") if "MALICIOUS" in s else "yellow"))
            elif s.startswith(("Tools used:", "ReAct steps:", "Summary:")):
                self._log_write(lid, Text(s, style="dim green"))
            else:
                self._log_write(lid, Text(s))

    @work(thread=True)
    def _run_incident_investigation(self, incident_id: str) -> None:
        lid = "#invest-log"
        self._log_write(lid, "[yellow]Running AI agent investigation (may take 5-30s)...[/yellow]")
        try:
            with _client(timeout=120) as c:
                r = c.post(f"{BASE}/ingest/incidents/{incident_id}/investigate")
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        data = r.json()
        if data.get("status") == "error":
            self._log_write(lid, f"[red]{data.get('message', 'Error')}[/red]")
            return

        verdict    = data.get("agent_verdict", "?")
        confidence = data.get("agent_confidence", 0)
        tools      = data.get("tools_used", [])
        steps      = data.get("agent_steps", 0)
        st         = sev_style(verdict.lower())

        self._log_write(lid, Rule(f"[{st}]Agent Verdict: {verdict}[/{st}]"))
        summary = Text()
        summary.append("Verdict:     ", style="dim")
        summary.append(f"{verdict}\n", style=f"bold {st}")
        summary.append("Confidence:  ", style="dim")
        summary.append(f"{confidence:.0%}\n", style="white")
        summary.append("Tools used:  ", style="dim")
        summary.append(f"{', '.join(tools)}\n", style="green")
        summary.append("ReAct steps: ", style="dim")
        summary.append(f"{steps}\n", style="white")
        self._log_write(lid, summary)

        # Now fetch the full report
        self._fetch_incident_report(incident_id)

    # ════════════════════════════════════════════════════════════════════════
    #  ASSESS
    # ════════════════════════════════════════════════════════════════════════
    @on(Button.Pressed, "#assess-btn")
    def _on_assess_btn(self, _: Button.Pressed) -> None:
        self._run_assess(
            self.query_one("#ml-score",      Input).value.strip(),
            self.query_one("#ioc-score",     Input).value.strip(),
            self.query_one("#tech-ids",      Input).value.strip(),
            self.query_one("#agent-verdict", Input).value.strip(),
        )

    @work(thread=True)
    def _run_assess(
        self, ml_s: str, ioc_s: str, tech_ids: str, verdict: str
    ) -> None:
        lid = "#assess-log"
        self._log_clear(lid)
        self._log_write(lid, "[cyan]Running assessment...[/cyan]")

        payload: dict = {}
        if ml_s:
            try:
                sc = float(ml_s)
                payload["ml"] = {
                    "score": sc, "is_malicious": sc >= 0.5,
                    "reason": "ML detection", "model_loaded": True,
                }
            except ValueError:
                pass
        if ioc_s:
            try:
                sc = float(ioc_s)
                payload["ioc"] = {
                    "score": sc, "is_malicious": sc >= 0.5,
                    "providers_hit": ["Local ThreatDB"], "indicator_count": 1,
                }
            except ValueError:
                pass
        if tech_ids:
            techs = [
                {"id": t.strip(), "name": t.strip(), "confidence": 0.85}
                for t in tech_ids.split(",") if t.strip()
            ]
            payload["mitre"] = {
                "techniques":            techs,
                "tactic_coverage":       ["execution"],
                "max_confidence":        0.85,
                "has_lateral_movement":  False,
                "has_credential_access": False,
                "has_impact":            False,
            }
        if verdict:
            payload["agent"] = {
                "verdict":         verdict.upper(),
                "confidence":      0.9,
                "tools_used":      ["lookup_ioc"],
                "reasoning_steps": 2,
            }

        if not payload:
            self._log_write(lid, "[red]Enter at least one signal.[/red]")
            return

        try:
            with _client(timeout=30) as c:
                d = c.post(f"{BASE}/assessment/analyze", json=payload).json()
        except Exception as e:
            self._log_write(lid, f"[red]{e}[/red]")
            return

        sev   = d.get("severity", "?")
        score = d.get("final_score", "?")
        conf  = d.get("confidence_level", "?")
        st    = sev_style(sev)

        self._log_clear(lid)
        self._log_write(lid, Rule(f"[{st}]Assessment Result  --  {sev.upper()}[/{st}]"))

        summary = Text()
        summary.append("Score:       ", style="dim")
        summary.append(f"{score}/100\n", style=f"bold {st}")
        summary.append("Severity:    ", style="dim")
        summary.append(f"{sev.upper()}\n", style=f"bold {st}")
        summary.append("Confidence:  ", style="dim")
        summary.append(f"{conf}\n", style="white")
        summary.append("Action:      ", style="dim")
        summary.append(d.get("recommended_action", ""), style="bold white")
        self._log_write(lid, summary)

        breakdown = d.get("score_breakdown", {})
        if breakdown:
            self._log_write(lid, Rule("[dim]Score Breakdown[/dim]"))
            for sig, val in breakdown.items():
                self._log_write(
                    lid, Text(f"  {sig.upper():<14} {val:.1f} pts", style="cyan")
                )

        trace = d.get("explanation_trace", [])
        if trace:
            self._log_write(lid, Rule("[dim]Explanation Trace[/dim]"))
            for i, line in enumerate(trace, 1):
                self._log_write(lid, Text(f"  {i}. {line}", style="dim"))


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    IrAgentTUI().run()
