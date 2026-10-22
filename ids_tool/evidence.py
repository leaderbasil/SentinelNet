# -*- coding: utf-8 -*-
"""
Evidence store: suspicious packets are saved as proof:
- a PCAP file (openable in Wireshark),
- a JSON summary file,
- a SHA-256 helper used to build the session manifest.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from .alerts import GREY, RESET


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidenceStore:
    def __init__(self, cfg, base_dir: Path, session_tag: str):
        self.max = int(cfg.logging.evidence_max_packets)
        self.pcap_path = base_dir / f"evidence_{session_tag}.pcap"
        self.meta_path = base_dir / f"evidence_{session_tag}.json"
        self._pk = []
        self._meta = []

    def add(self, pkt):
        if pkt is None or len(self._pk) >= self.max:
            return
        try:
            summary = pkt.summary()
        except Exception:
            summary = "<unprintable>"
        self._pk.append(pkt)
        self._meta.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "summary": summary,
        })

    def save(self):
        """Saves evidence at end of session; returns the PCAP path or None."""
        if not self._pk:
            return None
        try:
            self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
            from scapy.utils import wrpcap
            wrpcap(str(self.pcap_path), self._pk)
        except Exception as e:
            print(f"{GREY}[!] could not save evidence file: {e}{RESET}")
            return None
        try:
            self.meta_path.write_text(
                json.dumps(self._meta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
        return self.pcap_path
