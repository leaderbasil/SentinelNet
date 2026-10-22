# -*- coding: utf-8 -*-
"""
Deauth / Disassociation flood detector.
- Examines management frames: Dot11Deauth (subtype=12) and Disassociation (subtype=10).
- Counts frames per (source, BSSID) pair in a configurable time window.
- Records the Reason Code in the alert (useful for documentation).
- Works even with PMF: clients may ignore the forged frames, but we still
  see the sending attempts and alert on them.
"""
from __future__ import annotations

import time
from collections import deque

from scapy.all import Dot11

KIND_DEAUTH_FLOOD = "DEAUTH_FLOOD"


class DeauthDetector:
    def __init__(self, cfg, alerts, evidence=None, show_packets=True):
        self.cfg = cfg
        self.alerts = alerts
        self.evidence = evidence
        self.show_packets = show_packets
        self.window = float(cfg.deauth.window_seconds)
        self.threshold = int(cfg.deauth.alert_threshold)
        self.pairs = {}  # (source, BSSID) -> deque of frames in window

    def _reason(self, pkt):
        try:
            payload = pkt.getlayer("Dot11Deauth")
            if payload is not None:
                return int(payload.reason)
        except Exception:
            pass
        try:
            payload = pkt.getlayer("Dot11Disas")
            if payload is not None:
                return int(payload.reason)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    def process(self, pkt):
        dot = pkt.getlayer(Dot11)
        if dot is None or dot.type != 0:      # management frames only
            return
        if dot.subtype not in (10, 12):
            return

        label = "Disassociation" if dot.subtype == 10 else "Deauth"
        src = (dot.addr2 or "؟").lower()      # claimed sender (often spoofed)
        bssid = (dot.addr3 or src).lower()
        target = (dot.addr1 or "؟").lower()
        broadcast_target = target == "ff:ff:ff:ff:ff:ff"
        reason = self._reason(pkt)
        now = time.time()

        bucket = self.pairs.setdefault((src, bssid), deque())
        bucket.append((now, target, broadcast_target, reason))
        while bucket and (now - bucket[0][0]) > self.window:
            bucket.popleft()

        count = len(bucket)
        if self.show_packets:
            tgt_txt = "ALL devices (broadcast)" if broadcast_target else target
            print(f"    [WLAN] {label} frame #{count} in {self.window:.0f}s "
                  f"from {src} -> {tgt_txt}")

        if count >= self.threshold:
            n_broadcast = sum(1 for h in bucket if h[2])
            details = {
                "frame_count": count,
                "window": f"{self.window:.0f}s",
                "claimed_sender": src,
                "bssid": bssid,
                "target": "ALL devices (broadcast)" if n_broadcast else target,
                "reason_code": reason if reason is not None else "n/a",
                "note": "Repeated disconnection frames signal a classic Deauth Flood",
            }
            self.alerts.raise_alert(
                KIND_DEAUTH_FLOOD, "high",
                f"Possible Deauth Flood! {count} frames in {self.window:.0f}s",
                details,
                packet=pkt, evidence=self.evidence,
                dedupe_key=f"{src}|{bssid}|{int(now // self.window)}",
            )
