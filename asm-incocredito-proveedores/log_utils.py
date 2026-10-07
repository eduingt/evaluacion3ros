#!/usr/bin/env python3
"""
log_utils.py - Logging utility for ASM pipeline diagnosis.

Captures logs and errors to files for post-mortem analysis.
Zero dependencies beyond Python stdlib.

Quick start:
    from log_utils import get_logger

    log = get_logger("asm_scan")
    log.info("Processing %s...", domain)
    log.warning("DNS timeout for %s", domain)

    try:
        result = do_something()
    except Exception:
        log.exception("Failed for %s", domain)  # auto full traceback

Features:
  - Auto-created log directory (logs/ at project root)
  - Console output to stderr (captured by dashboard subprocess)
  - Rotating global pipeline log (logs/pipeline-<timestamp>.log)
  - Per-scan log file (dashboard_workspace/history/<scan_id>/scan.log)
  - Global exception hook captures unhandled crashes to log file
  - Stdout/stderr redirect helper for noisy libraries
"""

from __future__ import annotations

import logging
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_DIR = BASE_DIR / "logs"

LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured: set[str] = set()
_root_ready = False

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_dir(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    return d


def _file_handler(path: Path, level: int = logging.DEBUG) -> logging.FileHandler:
    fh = logging.FileHandler(str(path), encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return fh


def _console_handler(level: int = logging.INFO) -> logging.StreamHandler:
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return ch


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup(
    log_dir: Optional[Path] = None,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
) -> None:
    """
    One-shot global setup. Safe to call multiple times (idempotent).
    Configures root logger with:
      - File handler → logs/pipeline-<timestamp>.log
      - Console handler → stderr
      - Global exception hook
    """
    global _root_ready
    if _root_ready:
        return

    log_dir = _ensure_dir(log_dir or DEFAULT_LOG_DIR)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    root.addHandler(_file_handler(log_dir / f"pipeline-{ts}.log", file_level))
    root.addHandler(_console_handler(console_level))

    _install_excepthook()
    _root_ready = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger by name.  Calls setup() on first use if needed.
    Child loggers propagate to root for file + console output.
    """
    global _root_ready
    if not _root_ready:
        setup()

    log = logging.getLogger(name)
    if name not in _configured:
        log.setLevel(logging.DEBUG)
        _configured.add(name)
    return log


def capture_exception(
    logger: Optional[logging.Logger] = None,
    message: str = "Unhandled exception",
    level: int = logging.ERROR,
) -> str:
    """
    Log the current exception (from sys.exc_info()) with full traceback.
    Returns the formatted traceback string.

    Use inside except blocks:
        try:
            ...
        except Exception:
            tb = capture_exception(log, "DNS probe failed")
    """
    tb = traceback.format_exc()
    target = logger or logging.getLogger()
    target.log(level, "%s\n%s", message, tb)
    return tb


def exception_str(exc: Optional[BaseException] = None) -> str:
    """Format exception with full traceback as a string.

    Args:
        exc: Exception to format. If None, uses sys.exc_info().
    Returns:
        Formatted traceback string.
    """
    if exc is None:
        return traceback.format_exc()
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


# ---------------------------------------------------------------------------
# Per-scan logger (dashboard integration)
# ---------------------------------------------------------------------------


def scan_logger(scan_id: str, scan_dir: Path) -> logging.Logger:
    """
    Create/return a logger for a specific scan.
    Writes to scan_dir/scan.log in addition to global root handlers.

    Args:
        scan_id: Scan identifier (e.g. "20260526_143015_www.example.com")
        scan_dir: Scan output directory (already created)

    Returns:
        Logger instance bound to this scan.
    """
    log = get_logger(f"scan.{scan_id}")
    scan_dir = Path(scan_dir)
    _ensure_dir(scan_dir)
    fh = _file_handler(scan_dir / "scan.log")
    log.addHandler(fh)
    return log


# ---------------------------------------------------------------------------
# Global unhandled-exception hook
# ---------------------------------------------------------------------------

_original_excepthook = sys.excepthook


def _excepthook(exc_type, exc_value, exc_tb) -> None:
    """Global exception hook: writes to log, then falls through to original."""
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    try:
        logging.getLogger().error("UNHANDLED EXCEPTION\n%s", tb)
    except Exception:
        pass
    _original_excepthook(exc_type, exc_value, exc_tb)


def _install_excepthook() -> None:
    sys.excepthook = _excepthook


# ---------------------------------------------------------------------------
# Stdout/stderr redirect (optional)
# ---------------------------------------------------------------------------


class StdoutToLogger:
    """Redirect a stream (stdout/stderr) to a logger.

    Usage:
        import sys
        sys.stdout = StdoutToLogger(log, logging.INFO)
        sys.stderr = StdoutToLogger(log, logging.ERROR)
    """
    def __init__(self, logger: logging.Logger, level: int = logging.INFO):
        self.logger = logger
        self.level = level
        self._buf = ""

    def write(self, s: str) -> None:
        self._buf += s
        if "\n" in self._buf:
            lines = self._buf.split("\n")
            for line in lines[:-1]:
                stripped = line.rstrip()
                if stripped:
                    self.logger.log(self.level, stripped)
            self._buf = lines[-1]

    def flush(self) -> None:
        stripped = self._buf.rstrip()
        if stripped:
            self.logger.log(self.level, stripped)
        self._buf = ""
        try:
            sys.__stderr__.flush()
        except Exception:
            pass
