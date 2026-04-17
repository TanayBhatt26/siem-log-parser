#!/usr/bin/env python3
"""cli.py — SIEM Log Parser CLI v3.0"""

import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

import click
from parsers import parse, detect_format, PARSERS
from exporters import export, SUPPORTED_FORMATS

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False; console = None

SEV_COLORS = {"critical":"bold red","high":"bold yellow","medium":"yellow","low":"green"}
SEV_ICONS  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}

def _read_file(path):
    with open(path,"rb") as f: raw = f.read()
    if raw[:8] == b"ElfFile\x00": return raw.decode("latin-1"), True
    return raw.decode("utf-8", errors="replace"), False

def _banner():
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]🛡  SIEM Log Parser[/bold cyan]  [dim]v3.0 · GeoIP · SQLite · 8 Input Formats[/dim]",
            border_style="cyan"))

def _print_stats(events, detected, filename):
    counts = {}
    for e in events:
        k = (e.severity or "low").lower()
        counts[k] = counts.get(k,0)+1
    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column("k",style="dim"); t.add_column("v",style="bold white")
        t.add_row("File",filename)
        t.add_row("Format",f"[bold cyan]{detected}[/bold cyan]")
        t.add_row("Total",f"[bold white]{len(events)}[/bold white]")
        t.add_row("Critical",f"[bold red]{counts.get('critical',0)}[/bold red]")
        t.add_row("High",f"[bold yellow]{counts.get('high',0)}[/bold yellow]")
        t.add_row("Medium",f"[yellow]{counts.get('medium',0)}[/yellow]")
        t.add_row("Low",f"[green]{counts.get('low',0)}[/green]")
        geo_count = sum(1 for e in events if e.geo_country)
        mal_count = sum(1 for e in events if e.is_malicious)
        if geo_count: t.add_row("GeoIP enriched",f"[cyan]{geo_count}[/cyan]")
        if mal_count: t.add_row("Malicious IPs",f"[bold red]{mal_count}[/bold red]")
        console.print(Panel(t,title="[bold]Parse Summary[/bold]",border_style="cyan"))
    else:
        click.echo(f"\nFile:{filename}  Format:{detected}  Total:{len(events)}")
        for k,v in counts.items(): click.echo(f"  {k.upper()}:{v}")

def _render_table(events, limit=50, show_geo=False):
    base_cols = ["timestamp","severity","source_format","source_host","source_ip","dest_ip","event_type","event_action","username","message"]
    geo_cols  = ["geo_country","geo_city","geo_isp"]
    cols = base_cols + (geo_cols if show_geo else [])
    if not RICH:
        for evt in events[:limit]:
            d = evt.to_dict() if hasattr(evt,'to_dict') else evt
            click.echo(f"  {str(d.get('timestamp',''))[:19]}  {str(d.get('severity','')):8}  {str(d.get('source_ip','')):16}  {str(d.get('message',''))[:60]}")
        return
    t = Table(box=box.MINIMAL_DOUBLE_HEAD, header_style="bold cyan", border_style="dim", row_styles=["","dim"])
    widths = [20,10,10,14,14,14,16,16,14,36] + ([12,12,18] if show_geo else [])
    for col,w in zip(cols,widths):
        t.add_column(col.replace("_"," ").title(), max_width=w, no_wrap=True)
    for evt in events[:limit]:
        d = evt.to_dict() if hasattr(evt,'to_dict') else evt
        sev = (d.get("severity") or "low").lower()
        color = SEV_COLORS.get(sev,"white")
        row = [
            str(d.get("timestamp","") or "")[:19].replace("T"," "),
            f"[{color}]{SEV_ICONS.get(sev,'')} {sev.upper()}[/{color}]",
            str(d.get("source_format","") or "")[:10],
            str(d.get("source_host","") or "")[:14],
            str(d.get("source_ip","") or "")[:14],
            str(d.get("dest_ip","") or "")[:14],
            str(d.get("event_type","") or "")[:16],
            str(d.get("event_action","") or "")[:16],
            str(d.get("username","") or "")[:14],
            str(d.get("message","") or "")[:36],
        ]
        if show_geo:
            row += [
                str(d.get("geo_country","") or "")[:12],
                str(d.get("geo_city","") or "")[:12],
                str(d.get("geo_isp","") or "")[:18],
            ]
        t.add_row(*row)
    console.print(t)
    if len(events) > limit:
        console.print(f"  [dim]... {len(events)-limit} more (use --limit)[/dim]")


@click.group()
def cli():
    """🛡 SIEM Log Parser v3.0 — parse, enrich, store, query."""
    pass


@cli.command("parse")
@click.argument("file", type=click.Path(exists=True))
@click.option("-f","--format","input_fmt", default="auto", type=click.Choice(list(PARSERS.keys())+["auto"]))
@click.option("-o","--output","output_fmt", default="json", type=click.Choice(SUPPORTED_FORMATS))
@click.option("-d","--dest", default=None, help="Output file path")
@click.option("--index", default="siem-logs")
@click.option("--limit", default=50, show_default=True)
@click.option("--no-preview", is_flag=True)
@click.option("--enrich", "do_enrich", is_flag=True, help="Add GeoIP + threat intel enrichment")
@click.option("--dns",    "do_dns",    is_flag=True, help="Add reverse DNS (slower)")
@click.option("--store",  "do_store",  is_flag=True, help="Save events to SQLite DB")
@click.option("--abuseipdb-key", default="", help="AbuseIPDB API key for threat intel")
def parse_cmd(file, input_fmt, output_fmt, dest, index, limit, no_preview,
              do_enrich, do_dns, do_store, abuseipdb_key):
    """Parse a log file and export to chosen format."""
    _banner()
    content, is_binary = _read_file(file)
    detected = "evtx" if is_binary else (detect_format(content) if input_fmt=="auto" else input_fmt)
    fmt = detected if input_fmt=="auto" else input_fmt

    if RICH:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task(f"Parsing {os.path.basename(file)} as {fmt}...")
            if is_binary and fmt=="evtx":
                from parsers.evtx_parser import parse_evtx_file
                events = parse_evtx_file(file)
            else:
                events = parse(content, fmt=fmt)
    else:
        events = parse(content, fmt=fmt) if not is_binary else None

    if do_enrich:
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
                p.add_task("Enriching with GeoIP + threat intel...")
                from enrichers import enrich
                events = enrich(events, geoip=True, dns=do_dns,
                                threatintel=bool(abuseipdb_key), abuseipdb_key=abuseipdb_key or None)
        else:
            from enrichers import enrich
            events = enrich(events, geoip=True, dns=do_dns,
                            threatintel=bool(abuseipdb_key), abuseipdb_key=abuseipdb_key or None)

    if do_store:
        from storage.db import store_events
        import uuid
        sid = str(uuid.uuid4())[:8]
        n = store_events(events, session_id=sid, filename=os.path.basename(file), fmt=fmt)
        if RICH: console.print(f"[green]✓ Stored {n} events[/green] (session: [cyan]{sid}[/cyan])")

    _print_stats(events, detected, os.path.basename(file))
    result, _, ext = export(events, output_fmt, index=index)
    if dest is None:
        dest = f"{os.path.splitext(os.path.basename(file))[0]}_parsed.{ext}"
    if isinstance(result, str): result = result.encode("utf-8")
    with open(dest,"wb") as f: f.write(result)
    if RICH:
        console.print(f"\n[bold green]✓ Exported[/bold green] → [underline cyan]{dest}[/underline cyan]  [dim]({len(result):,} bytes)[/dim]")
    if not no_preview:
        _render_table(events, limit, show_geo=do_enrich)


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
@click.option("--enrich","do_enrich", is_flag=True)
def stats(file, input_fmt, do_enrich):
    """Show parse statistics and top IPs/users/actions."""
    _banner()
    content, _ = _read_file(file)
    detected = detect_format(content) if input_fmt=="auto" else input_fmt
    events = parse(content, fmt=detected)
    if do_enrich:
        from enrichers import enrich as _enrich
        events = _enrich(events, geoip=True)
    _print_stats(events, detected, os.path.basename(file))
    from collections import Counter
    ips     = Counter(e.source_ip    for e in events if e.source_ip)
    users   = Counter(e.username     for e in events if e.username)
    actions = Counter(e.event_action for e in events if e.event_action)
    if RICH:
        if ips:
            console.print("\n[bold]Top Source IPs:[/bold]")
            for ip,cnt in ips.most_common(5):
                geo = next((f" ([dim]{e.geo_country}[/dim])" for e in events if e.source_ip==ip and e.geo_country),"")
                console.print(f"  [cyan]{ip:<20}[/cyan]{geo}  {cnt} events")
        if users:
            console.print("\n[bold]Top Usernames:[/bold]")
            for u,cnt in users.most_common(5):
                console.print(f"  [yellow]{u:<20}[/yellow]  {cnt} events")
        if actions:
            console.print("\n[bold]Top Event Actions:[/bold]")
            for a,cnt in actions.most_common(5):
                console.print(f"  [green]{a:<25}[/green]  {cnt} events")


@cli.command()
@click.option("--severity",  default=None)
@click.option("--source-ip", default=None)
@click.option("--username",  default=None)
@click.option("--country",   default=None)
@click.option("--search",    default=None, help="Full-text search on message")
@click.option("--malicious", is_flag=True, help="Show only malicious IPs")
@click.option("--session",   default=None, help="Filter by session ID")
@click.option("--limit",     default=50, show_default=True)
@click.option("--format","output_fmt", default=None, help="Export results (json/csv/etc)")
def query(severity, source_ip, username, country, search, malicious, session, limit, output_fmt):
    """Query events stored in the local SQLite database."""
    _banner()
    from storage.db import query_events
    result = query_events(
        severity=severity, source_ip=source_ip, username=username,
        geo_country=country, search=search,
        is_malicious=True if malicious else None,
        session_id=session, limit=limit,
    )
    events = result["events"]
    if RICH:
        console.print(f"[bold]Found {result['total']} events[/bold]  [dim](showing {len(events)})[/dim]\n")
    if output_fmt:
        from schema import LogEvent
        log_events = []
        for d in events:
            e = LogEvent(**{k:v for k,v in d.items() if k in LogEvent.__dataclass_fields__})
            log_events.append(e)
        result_bytes, _, ext = export(log_events, output_fmt)
        dest = f"query_results.{ext}"
        if isinstance(result_bytes, str): result_bytes = result_bytes.encode()
        open(dest,"wb").write(result_bytes)
        if RICH: console.print(f"[green]✓ Saved[/green] → [cyan]{dest}[/cyan]")
    else:
        _render_table(events, limit, show_geo=True)


@cli.command("db-stats")
def db_stats():
    """Show statistics about events stored in the local database."""
    _banner()
    from storage.db import get_stats
    s = get_stats()
    if RICH:
        t = Table(box=box.ROUNDED, title="[bold]Database Statistics[/bold]", header_style="bold cyan")
        t.add_column("Metric"); t.add_column("Value", style="bold white")
        t.add_row("Total Events",   f"[white]{s['total_events']}[/white]")
        t.add_row("Malicious",      f"[red]{s['malicious']}[/red]")
        for sev, cnt in s.get("by_severity",{}).items():
            color = SEV_COLORS.get(sev,"white")
            t.add_row(f"Severity: {sev}", f"[{color}]{cnt}[/{color}]")
        console.print(t)
        if s.get("top_source_ips"):
            console.print("\n[bold]Top Source IPs:[/bold]")
            for item in s["top_source_ips"][:5]:
                console.print(f"  [cyan]{item['ip']:<20}[/cyan]  {item['count']} events")
        if s.get("top_countries"):
            console.print("\n[bold]Top Countries:[/bold]")
            for item in s["top_countries"][:5]:
                console.print(f"  [yellow]{item['country']:<20}[/yellow]  {item['count']} events")
        if s.get("sessions"):
            console.print("\n[bold]Recent Sessions:[/bold]")
            for sess in s["sessions"][:5]:
                console.print(f"  [dim]{sess['created_at'][:19]}[/dim]  [cyan]{sess['session_id']}[/cyan]  {sess['filename']} ({sess['event_count']} events)")
    else:
        click.echo(f"Total: {s['total_events']}  Malicious: {s['malicious']}")


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-f","--format","input_fmt", default="auto")
@click.option("--interval", default=2.0, show_default=True)
@click.option("--enrich","do_enrich", is_flag=True)
def watch(file, input_fmt, interval, do_enrich):
    """Watch a log file for new events live (tail -f style)."""
    _banner()
    if RICH: console.print(f"[bold cyan]Watching[/bold cyan] {file} — Ctrl+C to stop\n")
    seen = 0
    try:
        while True:
            lines = open(file,errors="replace").readlines()
            new = lines[seen:]
            if new:
                evts = parse("".join(new), fmt=detect_format("".join(new)) if input_fmt=="auto" else input_fmt)
                if do_enrich:
                    from enrichers import enrich as _enrich
                    evts = _enrich(evts, geoip=True)
                seen = len(lines)
                for evt in evts:
                    if not evt.message: continue
                    ts  = str(evt.timestamp or "")[:19].replace("T"," ")
                    sev = (evt.severity or "low").lower()
                    geo = f" [{evt.geo_country}]" if evt.geo_country else ""
                    mal = " [red]⚠ MALICIOUS[/red]" if evt.is_malicious and RICH else ""
                    if RICH:
                        color = SEV_COLORS.get(sev,"white")
                        console.print(f"[dim]{ts}[/dim]  [{color}]{SEV_ICONS.get(sev,'')} {sev.upper():<8}[/{color}]  [cyan]{str(evt.source_ip or ''):16}[/cyan]{geo}{mal}  {str(evt.message or '')[:60]}")
                    else:
                        click.echo(f"{ts}  {sev.upper():<8}  {str(evt.source_ip or ''):16}{geo}  {str(evt.message or '')[:60]}")
            time.sleep(interval)
    except KeyboardInterrupt:
        if RICH: console.print("\n[dim]Stopped.[/dim]")


@cli.command("list-formats")
def list_formats():
    """List all supported input and output formats."""
    _banner()
    if RICH:
        t = Table(title="Supported Formats", box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Type",style="bold"); t.add_column("Format"); t.add_column("Description")
        for fmt,desc in [
            ("syslog",         "RFC 5424 & 3164 — standard Unix/Linux syslog"),
            ("cef",            "ArcSight Common Event Format (Palo Alto, Cisco, Fortinet)"),
            ("leef",           "IBM QRadar LEEF v1.0 & v2.0"),
            ("json",           "JSON / NDJSON / ECS / OCSF — auto-maps 40+ aliases"),
            ("evtx",           "Windows Event Log XML + binary .evtx"),
            ("aws_cloudtrail", "AWS CloudTrail JSON (Records array)"),
            ("nginx",          "Nginx / Apache Combined & Error log format"),
            ("zeek",           "Zeek (Bro) conn/http/dns/notice/weird logs"),
        ]: t.add_row("INPUT", f"[cyan]{fmt}[/cyan]", desc)
        for fmt,desc in [
            ("json",          "Standard JSON array"),
            ("ndjson",        "Newline-delimited JSON"),
            ("csv",           "Comma-separated values"),
            ("excel",         "Excel .xlsx with color-coded severity"),
            ("elasticsearch", "Elasticsearch Bulk API (_bulk)"),
            ("splunk",        "Splunk HTTP Event Collector (HEC)"),
            ("stix",          "STIX 2.1 Bundle — threat intelligence"),
        ]: t.add_row("OUTPUT", f"[green]{fmt}[/green]", desc)
        console.print(t)
    else:
        click.echo("INPUT:  syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek")
        click.echo("OUTPUT: json|ndjson|csv|excel|elasticsearch|splunk|stix")

if __name__ == "__main__":
    cli()
