"""
╔══════════════════════════════════════════════════════════════════╗
║  CwX — Basic Antivirus Simulation (Signature & Heuristic)      ║
║                                                                  ║
║  A terminal-based cybersecurity tool demonstrating real-world    ║
║  antivirus architecture: signature scanning, Shannon entropy     ║
║  heuristic analysis, real-time filesystem monitoring, and        ║
║  automated quarantine isolation.                                 ║
║                                                                  ║
║  Author  : Maniya Jay                                           ║
║                                                                  ║
║  This tool is for EDUCATIONAL and ETHICAL use only.              ║
║  It does not detect real malware unless real signatures are       ║
║  added. It demonstrates concepts used by antivirus systems.      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time

# ── Force UTF-8 on Windows to prevent cp1252 encoding crashes ────
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.text import Text
from rich.align import Align
from rich.live import Live
from rich.columns import Columns
from rich import box

from scanner.engine import (
    load_signatures,
    calculate_sha256,
    quarantine_file,
    collect_files,
)
from scanner.heuristics import analyze_file, ENTROPY_THRESHOLD
from monitor.watcher import FolderMonitor
from utils.logger import log_event, get_log_path


# ── Configuration ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(__file__)
SCAN_TARGET = os.path.join(BASE_DIR, "scan_target")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")

# force_terminal bypasses the legacy Windows console renderer
# that cannot handle Unicode block characters
console = Console(force_terminal=True)


# ── ASCII Art Banner ─────────────────────────────────────────────
CWX_BANNER = """
[bold cyan]
   CCCCCC  W       W  X     X
  C        W       W   X   X
  C        W   W   W    X X
  C        W  W W  W   X   X
   CCCCCC   WW   WW   X     X
[/bold cyan]
"""

SUBTITLE = (
    "[dim white]Basic Antivirus Simulation[/dim white]  "
    "[bold yellow]│[/bold yellow]  "
    "[dim white]Signature & Heuristic Scanner[/dim white]  "
    "[bold yellow]│[/bold yellow]  "
    "[dim cyan]v2.0 - 2026[/dim cyan]"
)

AUTHOR_LINE = (
    "[dim]Developed by [bold bright_white]Maniya Jay [/bold bright_white]"
)


# ── Boot Sequence ────────────────────────────────────────────────

def display_boot_sequence() -> None:
    """Clear the terminal and display the CwX branded boot screen."""
    console.clear()
    console.print(Align.center(CWX_BANNER))
    console.print(Align.center(SUBTITLE))
    console.print(Align.center(AUTHOR_LINE))
    console.print()
    console.rule("[bold yellow]System Initialization[/bold yellow]", style="yellow")
    console.print()

    # Simulated boot checks for dramatic effect
    boot_steps = [
        ("Loading signature database", 0.4),
        ("Initializing SHA-256 hashing engine", 0.3),
        ("Calibrating Shannon entropy analyzer", 0.3),
        ("Preparing quarantine vault", 0.2),
        ("Starting real-time filesystem monitor", 0.4),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold white]{task.description}[/bold white]"),
        BarColumn(bar_width=30, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for step_name, duration in boot_steps:
            task = progress.add_task(step_name, total=100)
            for _ in range(100):
                time.sleep(duration / 100)
                progress.advance(task)

    console.print()
    console.print(
        Align.center(
            "[bold bright_green][+] All systems operational[/bold bright_green]"
        )
    )
    console.print()


# ── Single File Scan Pipeline ────────────────────────────────────

def scan_single_file(
    filepath: str,
    signatures: dict,
    results: list | None = None,
    live_print: bool = False,
) -> dict:
    """
    Run the full detection pipeline on a single file:
      1. SHA-256 hash computation
      2. Signature database lookup
      3. Heuristic entropy analysis (if no signature match)
      4. Quarantine (if threat confirmed)

    Returns a result dict for table rendering.
    """
    filename = os.path.basename(filepath)
    file_size = 0
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        pass

    # Step 1: Compute SHA-256 hash
    file_hash = calculate_sha256(filepath)
    if file_hash is None:
        result = {
            "file": filename,
            "path": filepath,
            "hash": "N/A",
            "size": file_size,
            "status": "ERROR",
            "detail": "Could not read file",
            "entropy": None,
            "severity": "MEDIUM",
        }
        if results is not None:
            results.append(result)
        return result

    # Step 2: Signature lookup
    if file_hash in signatures:
        threat = signatures[file_hash]
        threat_name = threat["name"] if isinstance(threat, dict) else str(threat)
        severity = threat.get("severity", "HIGH") if isinstance(threat, dict) else "HIGH"

        log_event(
            "THREAT_DETECTED",
            f"Signature match: {threat_name} in {filepath}",
            severity=severity,
            metadata={
                "file": filepath,
                "hash": file_hash,
                "threat_name": threat_name,
            },
        )

        # Step 4: Quarantine
        quarantined = quarantine_file(filepath)
        status = "QUARANTINED" if quarantined else "THREAT (quarantine failed)"

        result = {
            "file": filename,
            "path": filepath,
            "hash": file_hash[:16] + "..",
            "size": file_size,
            "status": status,
            "detail": threat_name,
            "entropy": None,
            "severity": severity,
        }

        if live_print:
            console.print(
                f"  [bold red][!!] THREAT:[/bold red] [white]{filename}[/white] "
                f"-> [bold]{threat_name}[/bold] "
                f"[dim]({status})[/dim]"
            )

        if results is not None:
            results.append(result)
        return result

    # Step 3: Heuristic analysis (no signature match)
    heuristic = analyze_file(filepath)

    if heuristic["suspicious"]:
        # High-entropy file — flag and quarantine
        quarantined = quarantine_file(filepath)
        status = "SUSPICIOUS (quarantined)" if quarantined else "SUSPICIOUS"

        result = {
            "file": filename,
            "path": filepath,
            "hash": file_hash[:16] + "…",
            "size": file_size,
            "status": status,
            "detail": heuristic["verdict"],
            "entropy": heuristic["entropy"],
            "severity": "HIGH",
        }

        if live_print:
            console.print(
                f"  [bold yellow][!?] SUSPICIOUS:[/bold yellow] [white]{filename}[/white] "
                f"-> Entropy {heuristic['entropy']:.4f} "
                f"[dim]({status})[/dim]"
            )
    else:
        # Clean file
        log_event(
            "FILE_CLEAN",
            f"No threat detected: {filepath}",
            severity="INFO",
            metadata={
                "file": filepath,
                "hash": file_hash,
                "entropy": heuristic["entropy"],
            },
        )
        result = {
            "file": filename,
            "path": filepath,
            "hash": file_hash[:16] + "…",
            "size": file_size,
            "status": "CLEAN",
            "detail": heuristic["verdict"],
            "entropy": heuristic["entropy"],
            "severity": "INFO",
        }

    if results is not None:
        results.append(result)
    return result


# ── Full Directory Scan ──────────────────────────────────────────

def run_full_scan(signatures: dict, target_dir: str = SCAN_TARGET) -> list:
    """
    Scan every file in the target directory with a Rich progress bar.
    """
    os.makedirs(target_dir, exist_ok=True)

    files = collect_files(target_dir)
    if not files:
        console.print(
            Panel(
                f"[yellow]No files found in {target_dir}.\n"
                "Place files there and scan again, or wait for the "
                "real-time monitor to detect new arrivals.[/yellow]",
                title="[bold yellow]Empty Target[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        log_event("SCAN_EMPTY", f"No files found in {target_dir}.", severity="INFO")
        return []

    log_event(
        "SCAN_START",
        f"Full scan initiated on {target_dir} ({len(files)} files)",
        severity="INFO",
        metadata={"directory": target_dir, "file_count": len(files)},
    )

    results = []
    console.print()

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold white]Scanning:[/bold white] {task.description}"),
        BarColumn(
            bar_width=40, complete_style="bright_green", finished_style="green"
        ),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Initializing...",
            total=len(files),
            status="",
        )

        for filepath in files:
            fname = os.path.basename(filepath)
            progress.update(task, description=fname[:35], status="analyzing...")
            result = scan_single_file(filepath, signatures, results)
            status_icon = (
                "[+] clean"
                if result["status"] == "CLEAN"
                else "[!!] THREAT" if "QUARANTINE" in result["status"].upper() else "[!?] flagged"
            )
            progress.update(task, advance=1, status=status_icon)

    log_event(
        "SCAN_COMPLETE",
        f"Scan finished: {len(results)} files processed.",
        severity="INFO",
        metadata={
            "total": len(results),
            "threats": sum(
                1 for r in results if r["status"] not in ("CLEAN", "ERROR")
            ),
        },
    )

    return results


# ── Results Table ────────────────────────────────────────────────

def display_results_table(results: list) -> None:
    """Render a color-coded results table using Rich."""
    if not results:
        return

    table = Table(
        title="[bold bright_white]Scan Results[/bold bright_white]",
        box=box.DOUBLE_EDGE,
        border_style="bright_cyan",
        header_style="bold bright_white on dark_blue",
        show_lines=True,
        padding=(0, 1),
    )

    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("File", style="white", max_width=25)
    table.add_column("SHA-256 (trunc)", style="dim cyan", width=20)
    table.add_column("Size", justify="right", style="dim", width=10)
    table.add_column("Entropy", justify="center", width=10)
    table.add_column("Status", justify="center", width=14)
    table.add_column("Detail", style="dim", max_width=40)

    for idx, r in enumerate(results, 1):
        # Color-code the status
        status = r["status"]
        if status == "CLEAN":
            status_styled = "[bold bright_green][+] CLEAN[/bold bright_green]"
        elif "QUARANTINE" in status.upper():
            status_styled = "[bold bright_red][X] THREAT[/bold bright_red]"
        elif "SUSPICIOUS" in status.upper():
            status_styled = "[bold bright_yellow][!?] SUSPECT[/bold bright_yellow]"
        elif status == "ERROR":
            status_styled = "[bold red][-] ERROR[/bold red]"
        else:
            status_styled = f"[white]{status}[/white]"

        # Format entropy
        entropy_str = (
            f"{r['entropy']:.2f}" if r["entropy"] is not None else "--"
        )

        # Format file size
        size_bytes = r.get("size", 0)
        if size_bytes > 1024 * 1024:
            size_str = f"{size_bytes / (1024*1024):.1f} MB"
        elif size_bytes > 1024:
            size_str = f"{size_bytes / 1024:.1f} KB"
        else:
            size_str = f"{size_bytes} B"

        table.add_row(
            str(idx),
            r["file"],
            r["hash"],
            size_str,
            entropy_str,
            status_styled,
            r["detail"][:40],
        )

    console.print()
    console.print(table)
    console.print()


# ── Summary Statistics ───────────────────────────────────────────

def display_summary(results: list) -> None:
    """Display a visual summary panel after the scan."""
    total = len(results)
    clean = sum(1 for r in results if r["status"] == "CLEAN")
    threats = sum(1 for r in results if "QUARANTINE" in r["status"].upper())
    suspicious = sum(1 for r in results if "SUSPICIOUS" in r["status"].upper())
    errors = sum(1 for r in results if r["status"] == "ERROR")

    summary_text = (
        f"[bold white]Files Scanned :[/bold white]  [bright_white]{total}[/bright_white]\n"
        f"[bold bright_green]Clean         :[/bold bright_green]  {clean}\n"
        f"[bold bright_red]Threats       :[/bold bright_red]  {threats}\n"
        f"[bold bright_yellow]Suspicious    :[/bold bright_yellow]  {suspicious}\n"
        f"[bold red]Errors        :[/bold red]  {errors}\n"
        f"\n[dim]Audit log → {get_log_path()}[/dim]"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold bright_white]:: Scan Summary[/bold bright_white]",
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            padding=(1, 3),
        )
    )


# ── Real-Time Monitor Callback ───────────────────────────────────

def realtime_scan_callback(filepath: str) -> None:
    """
    Callback invoked by the FolderMonitor whenever a new or modified
    file is detected. Runs the full scan pipeline and prints live output.
    """
    global _signatures
    console.print()
    console.rule("[bold cyan]Real-Time Detection[/bold cyan]", style="cyan")
    scan_single_file(filepath, _signatures, live_print=True)
    console.print()


# ── Interactive Menu ─────────────────────────────────────────────

def display_menu() -> None:
    """Display the main interactive command menu."""
    menu_text = (
        "[bold bright_white]1[/bold bright_white] [white]> Run Full Scan[/white]        "
        "[dim](scan all files in scan_target/)[/dim]\n"
        "[bold bright_white]2[/bold bright_white] [white]> Monitor Mode[/white]         "
        "[dim](real-time watchdog surveillance)[/dim]\n"
        "[bold bright_white]3[/bold bright_white] [white]> View Audit Logs[/white]      "
        "[dim](display recent log entries)[/dim]\n"
        "[bold bright_white]4[/bold bright_white] [white]> System Info[/white]           "
        "[dim](architecture & config overview)[/dim]\n"
        "[bold bright_white]5[/bold bright_white] [white]> Scan Custom Path[/white]      "
        "[dim](scan any specific file or folder on your system)[/dim]\n"
        "[bold bright_white]0[/bold bright_white] [white]> Exit[/white]                 "
        "[dim](shutdown all systems)[/dim]"
    )

    console.print(
        Panel(
            menu_text,
            title="[bold bright_white]>> Command Center[/bold bright_white]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def view_audit_logs() -> None:
    """Display the last 15 audit log entries in a formatted panel."""
    log_path = get_log_path()
    if not os.path.exists(log_path):
        console.print("[yellow]No audit logs found yet.[/yellow]")
        return

    import json

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Show last 15 entries
    recent = lines[-15:] if len(lines) > 15 else lines

    table = Table(
        title="[bold white]Recent Audit Log Entries[/bold white]",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        header_style="bold white on dark_blue",
    )
    table.add_column("Timestamp", style="dim cyan", width=22)
    table.add_column("Event", style="white", width=22)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Message", style="dim", max_width=50)

    for line in recent:
        try:
            entry = json.loads(line.strip())
            sev = entry.get("severity", "INFO")
            if sev == "CRITICAL":
                sev_style = f"[bold red]{sev}[/bold red]"
            elif sev == "HIGH":
                sev_style = f"[bold bright_red]{sev}[/bold bright_red]"
            elif sev == "MEDIUM":
                sev_style = f"[bold yellow]{sev}[/bold yellow]"
            else:
                sev_style = f"[dim]{sev}[/dim]"

            ts = entry.get("timestamp", "")[:19]
            table.add_row(
                ts,
                entry.get("event_type", ""),
                sev_style,
                entry.get("message", "")[:50],
            )
        except (json.JSONDecodeError, KeyError):
            pass

    console.print()
    console.print(table)
    console.print(f"\n[dim]Full log file: {log_path}[/dim]\n")


def display_system_info() -> None:
    """Show architecture and configuration overview."""
    info = (
        "[bold bright_white]Architecture[/bold bright_white]\n"
        "[dim]---------------------------------------------[/dim]\n"
        "  [cyan]Detection Layer 1:[/cyan]  SHA-256 Signature Matching\n"
        "  [cyan]Detection Layer 2:[/cyan]  Shannon Entropy Heuristic Analysis\n"
        "  [cyan]Response Engine :[/cyan]   Automated Quarantine Isolation\n"
        "  [cyan]Monitoring      :[/cyan]   Watchdog Real-Time FS Events\n"
        "  [cyan]Logging Format  :[/cyan]   JSONL (SIEM-Compatible)\n"
        "\n"
        "[bold bright_white]Configuration[/bold bright_white]\n"
        "[dim]---------------------------------------------[/dim]\n"
        f"  [cyan]Scan Target     :[/cyan]  {SCAN_TARGET}\n"
        f"  [cyan]Quarantine Dir  :[/cyan]  {QUARANTINE_DIR}\n"
        f"  [cyan]Entropy Threshold:[/cyan] {ENTROPY_THRESHOLD} bits/byte\n"
        f"  [cyan]Hash Algorithm  :[/cyan]  SHA-256 (256-bit, NIST standard)\n"
        f"  [cyan]Chunk Size      :[/cyan]  8192 bytes (memory-safe)\n"
        f"  [cyan]Log Path        :[/cyan]  {get_log_path()}\n"
        "\n"
        "[bold bright_white]2026 Relevance[/bold bright_white]\n"
        "[dim]─────────────────────────────────────────[/dim]\n"
        "  This tool demonstrates foundational principles that modern\n"
        "  EDR/XDR platforms (CrowdStrike, SentinelOne, Defender ATP)\n"
        "  use as their first evaluation layer before applying behavioral\n"
        "  analysis, ML models, and cloud threat intelligence.\n"
    )

    console.print(
        Panel(
            info,
            title="[bold bright_white]<< System Architecture >>[/bold bright_white]",
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            padding=(1, 2),
        )
    )


# ── Main Entry Point ─────────────────────────────────────────────
# Global reference for monitor callback
_signatures: dict = {}


def main() -> None:
    """Main application loop with interactive menu."""
    global _signatures

    try:
        # Phase 1: Boot sequence
        display_boot_sequence()

        # Phase 2: Load signature database
        _signatures = load_signatures()
        sig_count = len(_signatures)
        console.print(
            f"  [bright_green][+][/bright_green] "
            f"[white]Signature database loaded:[/white] "
            f"[bold bright_cyan]{sig_count}[/bold bright_cyan] known threats\n"
        )

        # Phase 3: Ensure directories exist
        os.makedirs(SCAN_TARGET, exist_ok=True)
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        # Monitor instance (initialized but not started until user selects it)
        monitor = FolderMonitor(SCAN_TARGET, realtime_scan_callback)

        # Phase 4: Interactive command loop
        while True:
            console.rule(style="dim")
            display_menu()
            choice = console.input(
                "\n[bold bright_cyan]  cwx>[/bold bright_cyan] "
            ).strip()

            if choice == "1":
                console.rule(
                    "[bold bright_white]Full System Scan[/bold bright_white]",
                    style="bright_green",
                )
                results = run_full_scan(_signatures)
                if results:
                    display_results_table(results)
                    display_summary(results)

            elif choice == "2":
                if monitor.is_running:
                    console.print(
                        "[yellow]  Monitor is already running. "
                        "Drop files into scan_target/ to trigger scans.[/yellow]\n"
                    )
                else:
                    monitor.start()
                    console.print(
                        Panel(
                            "[bold bright_green]Real-time monitoring is now ACTIVE.[/bold bright_green]\n\n"
                            "[white]Drop any file into [bold]scan_target/[/bold] and it will be "
                            "scanned instantly.[/white]\n"
                            "[dim]Press Ctrl+C at any time to stop.[/dim]",
                            title="[bold][*] LIVE MONITOR[/bold]",
                            border_style="bright_red",
                            box=box.HEAVY,
                            padding=(1, 2),
                        )
                    )
                    # Keep the monitor alive until user goes back
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        monitor.stop()
                        console.print(
                            "\n[dim]Monitor stopped. Returning to menu...[/dim]\n"
                        )

            elif choice == "3":
                view_audit_logs()

            elif choice == "4":
                display_system_info()

            elif choice == "5":
                console.print()
                custom_path = console.input("[bold cyan]  Enter full file or folder path to scan: [/bold cyan]").strip()
                # Remove surrounding quotes if the user drag-and-dropped the file
                custom_path = custom_path.strip('\'"')
                
                if not os.path.exists(custom_path):
                    console.print(f"\n[bold red]  [-] Error: Path '{custom_path}' does not exist.[/bold red]\n")
                elif os.path.isfile(custom_path):
                    console.rule(f"[bold bright_white]Scanning File: {os.path.basename(custom_path)}[/bold bright_white]", style="bright_green")
                    results = []
                    scan_single_file(custom_path, _signatures, results)
                    if results:
                        display_results_table(results)
                elif os.path.isdir(custom_path):
                    console.rule(f"[bold bright_white]Scanning Directory: {custom_path}[/bold bright_white]", style="bright_green")
                    results = run_full_scan(_signatures, target_dir=custom_path)
                    if results:
                        display_results_table(results)
                        display_summary(results)

            elif choice == "0":
                monitor.stop()
                console.print(
                    "\n[bold bright_cyan]  Shutting down CwX systems...[/bold bright_cyan]"
                )
                log_event("SHUTDOWN", "CwX terminated by user.", severity="INFO")
                console.print(
                    "[dim]  All processes terminated. Stay ethical.\n[/dim]"
                )
                sys.exit(0)

            else:
                console.print("[red]  Invalid option. Try again.[/red]")

    except KeyboardInterrupt:
        # ── Graceful Exit Override ────────────────────────────────
        # Spec requirement: on Ctrl+C, print exactly this message.
        print("\nhow did you know ?")
        sys.exit(0)


if __name__ == "__main__":
    main()
