# -*- coding: utf-8 -*-
"""
Alerts system: colored console output + JSONL evidence log.
Severity is high / medium / info. All console text is English for clarity.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import init as _colorama_init
    _colorama_init()
except Exception:
    pass

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GREY = "\033[90m"
BOLD = "\033[1m"

SEVERITY_COLORS = {"high": RED, "medium": YELLOW, "info": CYAN}


class AlertManager:
    """Single place for every alert: screen + JSONL evidence file."""

    def __init__(self, cfg, log_file: Path | None = None):
        self.cfg = cfg
        self.cooldown = float(getattr(cfg.alerts, "cooldown_seconds", 15.0))
        self.log_file = log_file
        self._recent = {}      # dedupe key -> [last_shown_time, suppressed_repeats]
        self.kinds = {}        # alert kind -> count
        self.total_alerts = 0

    def raise_alert(self, kind, severity, title, details=None, packet=None,
                    evidence=None, dedupe_key=None):
        key = f"{kind}|{dedupe_key or json.dumps(details, sort_keys=True, default=str)}"
        now = time.time()
        entry = self._recent.get(key)

        if entry and (now - entry[0]) < self.cooldown:
            entry[1] += 1
            return False  # repeat suppressed, only counted

        repeat_note = ""
        if entry and entry[1]:
            repeat_note = f" (ongoing: repeated {entry[1]} more times)"

        self._recent[key] = [now, 0]
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        self.total_alerts += 1

        record = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "severity": severity,
            "title": title,
            "details": details or {},
        }

        color = SEVERITY_COLORS.get(severity, GREY)
        print(f"{color}{BOLD}[ALERT-{severity}]{RESET} {color}WARNING: {title}{repeat_note}{RESET}")
        for k, v in (details or {}).items():
            print(f"      -> {k}: {v}")

        if self.log_file is not None:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError:
                pass

        if evidence is not None:
            try:
                evidence.add(packet)
            except Exception:
                pass

        return True
