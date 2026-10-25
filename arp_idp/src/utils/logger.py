"""Minimal logging + UTF-8 console setup (mirrors rugscan's helper)."""

from __future__ import annotations

import contextlib
import logging
import sys


def utf8_stdout() -> None:
    # Windows consoles default to cp1252; our reports contain ≥ / → / × glyphs.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):
                stream.reconfigure(encoding="utf-8")


def silence_scapy() -> None:
    """Hide Scapy's 'No libpcap provider available' import warning.

    It only concerns live capture; reading PCAP files is unaffected. Must run
    before Scapy is first imported, so call it at startup.
    """
    import logging
    import warnings
    for name in ("scapy", "scapy.loading", "scapy.runtime", "scapy.interactive"):
        logging.getLogger(name).setLevel(logging.ERROR)
    warnings.filterwarnings("ignore", module="scapy")


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
