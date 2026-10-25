"""Settings and config loading for the ARP IDP (mirrors rugscan/config)."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DEFAULT_DATA_DIR = ROOT / "test_data"
DEFAULT_REPORTS_DIR = ROOT / "reports"


@dataclass(frozen=True)
class Settings:
    weights_path: Path = CONFIG_DIR / "signal_weights.yaml"
    data_dir: Path = DEFAULT_DATA_DIR
    reports_dir: Path = DEFAULT_REPORTS_DIR
    default_baseline: Path = DEFAULT_DATA_DIR / "baseline.json"


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@functools.lru_cache(maxsize=4)
def load_weights(path: str | None = None) -> dict:
    p = Path(path) if path else get_settings().weights_path
    with open(p) as fh:
        cfg = yaml.safe_load(fh)
    # fail fast: every declared signal must resolve to a base weight
    bw = cfg["base_weight"]
    for name, spec in cfg["signals"].items():
        if spec["severity"] not in bw:
            raise ValueError(f"signal {name}: severity {spec['severity']} has no base_weight")
    return cfg
