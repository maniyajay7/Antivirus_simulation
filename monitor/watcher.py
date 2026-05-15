"""
monitor/watcher.py — Real-Time Filesystem Monitor (Watchdog)

Uses the `watchdog` library to provide live, event-driven monitoring
of a target directory. When a new file is created or an existing file
is modified, the watcher instantly triggers a scan of that file
against both the signature database and the heuristic engine.

This mirrors real-world Endpoint Detection & Response (EDR) agents
that hook into OS filesystem events (inotify on Linux, ReadDirectoryChangesW
on Windows) to detect threats the moment they land on disk — before
the user ever opens them.

Author : Maniya Jay Maheshbhai (24DCS050)
Project: CwX Antivirus Simulation — DEPSTAR
"""

import os
import time
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from utils.logger import log_event


class ThreatHandler(FileSystemEventHandler):
    """
    Custom watchdog event handler that triggers on-demand scans
    whenever a file is created or modified in the monitored directory.

    Parameters
    ----------
    scan_callback : callable
        A function that accepts a single file path string and performs
        the full scan pipeline (hash → signature → heuristic → quarantine).
    """

    def __init__(self, scan_callback: Callable[[str], None]) -> None:
        super().__init__()
        self.scan_callback = scan_callback

    def on_created(self, event: FileSystemEvent) -> None:
        """Fired when a new file appears in the monitored directory."""
        if not event.is_directory:
            # Small delay to ensure the file write is complete
            time.sleep(0.3)
            log_event(
                "REALTIME_DETECT",
                f"New file detected: {event.src_path}",
                severity="INFO",
                metadata={"event": "created", "path": event.src_path},
            )
            self.scan_callback(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Fired when an existing file is modified in-place."""
        if not event.is_directory:
            time.sleep(0.3)
            log_event(
                "REALTIME_DETECT",
                f"File modification detected: {event.src_path}",
                severity="INFO",
                metadata={"event": "modified", "path": event.src_path},
            )
            self.scan_callback(event.src_path)


class FolderMonitor:
    """
    Manages the watchdog Observer lifecycle for a given directory.

    Usage
    -----
        monitor = FolderMonitor(target_dir, scan_function)
        monitor.start()   # begins background monitoring
        ...
        monitor.stop()    # gracefully shuts down the observer thread
    """

    def __init__(
        self, target_dir: str, scan_callback: Callable[[str], None]
    ) -> None:
        self.target_dir = target_dir
        self.observer: Optional[Observer] = None
        self.handler = ThreatHandler(scan_callback)

    def start(self) -> None:
        """
        Start the background observer thread.

        The observer runs as a daemon thread, so it will not prevent
        the main process from exiting when the user hits Ctrl+C.
        """
        os.makedirs(self.target_dir, exist_ok=True)

        self.observer = Observer()
        self.observer.schedule(
            self.handler,
            path=self.target_dir,
            recursive=True,  # Monitor all subdirectories
        )
        self.observer.daemon = True
        self.observer.start()

        log_event(
            "MONITOR_START",
            f"Real-time monitoring active on: {self.target_dir}",
            severity="INFO",
            metadata={"directory": self.target_dir},
        )

    def stop(self) -> None:
        """Gracefully stop the observer and join the thread."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3)
            log_event(
                "MONITOR_STOP",
                "Real-time monitoring terminated gracefully.",
                severity="INFO",
            )

    @property
    def is_running(self) -> bool:
        """Check if the observer thread is still alive."""
        return self.observer is not None and self.observer.is_alive()
