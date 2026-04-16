#!/usr/bin/env python3
"""cli.py — SIEM Log Parser CLI"""

import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

import click
from parsers import parse, detect_format, PARSERS
from exporters import export, SUPPORTED_FORMATS

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

SEV_COLORS = {"critical":"bold red","high":"bold yellow","medium":"yellow","low":"green"}
SEV_ICONS  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}

def _read_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:8] == b"ElfFile\x00":
        return raw.decode("latin-1"), True
    return raw.decode("utf-8", errors="replace"), False

def _banner():
    if RICH:
        console.print(Panel.fit("[bold cyan]🛡  SIEM Log Parser[/bold cyan]  [dim]Universal Log Normalization Pipeline[/dim]", border_style="cyan"))

def _stats(events, detected, filename):
    counts = {}
    for e in events:
        k = (e.severity or "low").lower()
        counts[k] = counts.get(k, 0) + 1
    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column("k", style="dim"); t.add_column("v", style="bold white")
        t.add_row("File", filename)
        t.add_row("Detected Format", f"[bold cyan]{detected}[/bold cyan]")
        t.add_row("Total Events", f"[bold white]{len(events)}[/bold white]")
        t.add_row("Critical", f"[bold red]{counts.get('critical',0)}[/bold red]")
        t.add_row("High",     f"[bold yellow]{counts.get('high',0)}[/bold yellow]")
        t.add_row("Medium",   f"[yellow]{counts.get('medium',0)}[/yellow]")
        t.add_row("Low",      f"[green]{counts.get('low',0)}[/green]")
        console.print(Panel(t, title="[bold]Parse Summary[/bold]", border_style="cyan"))
    else:
        click.echo(f"\nFile: {filename}  Format: {detected}  Total: {len(events)}")
        for k,v in counts.items(): click.echo(f"  {k.upper()}: {v}")

def _table(events, limit=50):
    cols = ["timestamp","severity","source_format","source_host","source_ip",
            "dest_ip","event_type","event_action","username","message"]
    if RICH:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD, header_style="bold cyan", border_style="dim", row_styles=["","dim"])
        widths = [20,10,10,14,14,14,16,16,14,36]
        for col, w in zip(cols, widths):
            t.add_column(col.replace("_"," ").title(), max_width=w, no_wrap=True)
        for evt in events[:limit]:
            sev = (evt.severity or "low").lower()
            color = SEV_COLORS.get(sev,"white")
            row = [
                str(evt.timestamp or "")[:19].replace("T"," "),
                f"[{color}]{SEV_ICONS.get(sev,'')} {sev.upper()}[/{color}]",
                evt.source_format or "",
                str(evt.source_host or "")[:14],
                str(evt.source_ip or "")[:14],
                str(evt.dest_ip or "")[:14],
                str(evt.event_type or "")[:16],
                str(evt.event_action or "")[:16],
                str(evt.username or "")[:14],
                str(evt.message or "")[:36],
            ]
            t.add_row(*row)
        console.print(t)
        if len(events) > limit:
            console.print(f"  [dim]... {len(events)-limit} more events (use --limit)[/dim]")
    else:
        for evt in events[:limit]:
            click.echo(f"  {str(evt.timestamp or '')[:19]}  {str(evt.severity or ''):8}  {str(evt.source_ip or ''):16}  {str(evt.message or '')[:60]}")

@click.group()
def cli():
    """🛡 SIEM Log Parser — Universal log normalization tool."""
    pass

@cli.command("parse")
@click.argument("file", type=click.Path(exists=True))
@click.option("-f","--format","input_fmt", default="auto", type=click.Choice(list(PARSERS.keys())+["auto"]))
@click.option("-o","--output","output_fmt", default="json", type=click.Choice(SUPPORTED_FORMATS))
@click.option("-d","--dest", default=None, help="Output file path")
@click.option("--index", default="siem-logs", help="Elasticsearch index name")
@click.option("--limit", default=50, show_default=True)
@click.option("--no-preview", is_flag=True)
def parse_cmd(file, input_fmt, output_fmt, dest, index, limit, no_preview):
    """Parse a log file and export to chosen format."""
    _banner()
    content, is_binary = _read_file(file)
    detected = "evtx" if is_binary else (detect_format(content) if input_fmt == "auto" else input_fmt)
    fmt = detected if input_fmt == "auto" else input_fmt

    if is_binary and fmt == "evtx":
        from parsers.evtx_parser import parse_evtx_file
        events = parse_evtx_file(file)
    else:
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
                p.add_task(f"Parsing {os.path.basename(file)} as {fmt}...")
                events = parse(content, fmt=fmt)
        else:
            click.echo(f"Parsing {file} as {fmt}...")
            events = parse(content, fmt=fmt)

    _stats(events, detected, os.path.basename(file))
    result, mime, ext = export(events, output_fmt, index=index)
    if dest is None:
        dest = f"{os.path.splitext(os.path.basename(file))[0]}_parsed.{ext}"
    if isinstance(result, str):
        result = result.encode("utf-8")
    with open(dest, "wb") as f:
        f.write(result)
    if RICH:
        console.print(f"\n[bold green]✓ Exported[/bold green] → [underline cyan]{dest}[/underline cyan]  [dim]({len(result):,} bytes)[/dim]")
    else:
        click.echo(f"Exported → {dest} ({len(result):,} bytes)")
    if not no_preview:
        _table(events, limit)

@cli.command()
@click.argument("file", type=click.Path(exists=True))
def detect(file):
    """Auto-detect the format of a log file."""
    content, is_binary = _read_file(file)
    fmt = "evtx" if is_binary else detect_format(content)
    _banner()
    if RICH: console.print(f"\n[bold]{file}[/bold]  →  [bold cyan]{fmt}[/bold cyan]")
    else: click.echo(f"Detected: {fmt}")

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-f","--format","input_fmt", default="auto")
def stats(file, input_fmt):
    """Show parse statistics and top IPs/users/actions."""
    _banner()
    content, _ = _read_file(file)
    detected = detect_format(content) if input_fmt == "auto" else input_fmt
    events = parse(content, fmt=detected)
    _stats(events, detected, os.path.basename(file))
    from collections import Counter
    ips     = Counter(e.source_ip    for e in events if e.source_ip)
    users   = Counter(e.username     for e in events if e.username)
    actions = Counter(e.event_action for e in events if e.event_action)
    if RICH:
        if ips:
            console.print("\n[bold]Top Source IPs:[/bold]")
            for ip, cnt in ips.most_common(5):
                console.print(f"  [cyan]{ip:<20}[/cyan] {cnt} events")
        if users:
            console.print("\n[bold]Top Usernames:[/bold]")
            for u, cnt in users.most_common(5):
                console.print(f"  [yellow]{u:<20}[/yellow] {cnt} events")
        if actions:
            console.print("\n[bold]Top Event Actions:[/bold]")
            for a, cnt in actions.most_common(5):
                console.print(f"  [green]{a:<25}[/green] {cnt} events")
    else:
        for ip, cnt in ips.most_common(5): click.echo(f"  IP: {ip} ({cnt})")
        for u, cnt in users.most_common(5): click.echo(f"  User: {u} ({cnt})")

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-f","--format","input_fmt", default="auto")
@click.option("--interval", default=2.0, show_default=True)
def watch(file, input_fmt, interval):
    """Watch a log file live for new events (tail -f style)."""
    _banner()
    if RICH: console.print(f"[bold cyan]Watching[/bold cyan] {file} — Ctrl+C to stop\n")
    else: click.echo(f"Watching {file} — Ctrl+C to stop")
    seen = 0
    try:
        while True:
            lines = open(file, errors="replace").readlines()
            new = lines[seen:]
            if new:
                evts = parse("".join(new), fmt=detect_format("".join(new)) if input_fmt=="auto" else input_fmt)
                seen = len(lines)
                for evt in evts:
                    if not evt.message: continue
                    ts  = str(evt.timestamp or "")[:19].replace("T"," ")
                    sev = (evt.severity or "low").lower()
                    if RICH:
                        color = SEV_COLORS.get(sev,"white")
                        console.print(f"[dim]{ts}[/dim]  [{color}]{SEV_ICONS.get(sev,'')} {sev.upper():<8}[/{color}]  [cyan]{str(evt.source_ip or ''):16}[/cyan]  {str(evt.message or '')[:70]}")
                    else:
                        click.echo(f"{ts}  {sev.upper():<8}  {str(evt.source_ip or ''):16}  {str(evt.message or '')[:70]}")
            time.sleep(interval)
    except KeyboardInterrupt:
        if RICH: console.print("\n[dim]Stopped.[/dim]")

@cli.command("list-formats")
def list_formats():
    """List all supported input and output formats."""
    _banner()
    if RICH:
        t = Table(title="Supported Formats", box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Type", style="bold"); t.add_column("Format"); t.add_column("Description")
        for fmt, desc in [
            ("syslog","RFC 5424 & 3164 — standard Unix/Linux syslog"),
            ("cef",   "ArcSight Common Event Format (Palo Alto, Cisco, Fortinet)"),
            ("leef",  "IBM QRadar LEEF v1.0 & v2.0"),
            ("json",  "JSON / NDJSON / ECS / OCSF — auto-maps 40+ field aliases"),
            ("evtx",  "Windows Event Log XML + binary .evtx (python-evtx)"),
        ]: t.add_row("INPUT", f"[cyan]{fmt}[/cyan]", desc)
        for fmt, desc in [
            ("json",          "Standard JSON array"),
            ("ndjson",        "Newline-delimited JSON (streaming)"),
            ("csv",           "Comma-separated values"),
            ("excel",         "Excel .xlsx with color-coded severity rows"),
            ("elasticsearch", "Elasticsearch Bulk API (_bulk endpoint)"),
            ("splunk",        "Splunk HTTP Event Collector (HEC)"),
            ("stix",          "STIX 2.1 Bundle — threat intelligence sharing"),
        ]: t.add_row("OUTPUT", f"[green]{fmt}[/green]", desc)
        console.print(t)
    else:
        click.echo("INPUT:  syslog | cef | leef | json | evtx")
        click.echo("OUTPUT: json | ndjson | csv | excel | elasticsearch | splunk | stix")

if __name__ == "__main__":
    cli()
