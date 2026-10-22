# -*- coding: utf-8 -*-
"""Shared helpers: project path + a silent alert recorder for tests."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class Recorder:
    """Duck-typed AlertManager replacement that records alerts silently."""

    cooldown = 0

    def __init__(self):
        self.alerts = []
        self.total_alerts = 0
        self.kinds = {}

    def raise_alert(self, kind, severity, title, details=None, packet=None,
                    evidence=None, dedupe_key=None):
        self.alerts.append({"kind": kind, "severity": severity,
                            "title": title, "details": details or {}})
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        self.total_alerts += 1
        return True
