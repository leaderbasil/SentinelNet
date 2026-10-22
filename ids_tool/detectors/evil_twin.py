# -*- coding: utf-8 -*-
"""
Evil Twin (rogue AP) detector.
Sources: Beacon frames (subtype=8) and Probe Responses (subtype=5).
Extracted info: SSID, BSSID, channel, security (RSN/WPA elements).
Rules (separates the legitimate AP from a suspicious one):
1) Unknown BSSID advertising an SSID listed in the allowed-APs baseline -> high.
2) Same SSID from different BSSIDs (no baseline set) -> high.
3) Channel or security change for a known BSSID -> medium.
4) AP completely unknown to the baseline -> info (UNKNOWN_AP).
"""
from __future__ import annotations

import time
from pathlib import Path

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp

from ..alerts import CYAN, RESET
from ..config import PROJECT_ROOT

KIND_EVIL_TWIN = "EVIL_TWIN"
KIND_PRIVACY_CHANGE = "BEACON_PRIVACY_CHANGE"
KIND_CHANNEL_CHANGE = "AP_CHANNEL_CHANGE"
KIND_UNKNOWN_AP = "UNKNOWN_AP"


def _norm_mac(m):
    return (m or "").strip().lower()


def _iter_elts(pkt):
    try:
        elt = pkt.getlayer(Dot11Elt)
    except Exception:
        return
    while elt is not None:
        yield elt
        payload = elt.payload
        elt = payload if isinstance(payload, Dot11Elt) else None


def extract_ssid(pkt):
    for elt in _iter_elts(pkt):
        try:
            if int(elt.ID) == 0:
                return bytes(elt.info or b"").decode("utf-8", "replace").strip()
        except Exception:
            pass
    return ""


def extract_beacon_channel(pkt):
    for elt in _iter_elts(pkt):
        try:
            if int(elt.ID) == 3 and elt.info:
                return int.from_bytes(bytes(elt.info), "big")
        except Exception:
            pass
    return None


def security_label(resp_obj, pkt):
    """Describes the protection type from RSN/WPA elements if present."""
    for elt in _iter_elts(pkt):
        try:
            eid = int(elt.ID)
        except Exception:
            continue
        if eid == 48:   # RSN IE -> WPA2/WPA3
            return "WPA2/WPA3 (RSN)"
        if eid == 221 and bytes(elt.info or b"").startswith(b"\x00P\xf2\x01"):
            return "WPA1"
    try:
        if resp_obj is not None and (int(resp_obj.cap) & 0x0010):
            return "encrypted (unspecified)"
    except Exception:
        pass
    return "open"


def load_allowed_aps(path):
    """Loads the allowed-AP baseline from a YAML file. Returns (map, ssid_set)."""
    if not path:
        return {}, set()
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    if not p.exists():
        return {}, set()
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    except Exception as e:
        print(f"[baseline] could not read {p}: {e}")
        return {}, set()
    entries = {}
    for e in data:
        ssid = str(e.get("ssid", "")).strip()
        bssid = _norm_mac(e.get("bssid"))
        if ssid and bssid:
            entries[(ssid.lower(), bssid)] = {
                "channel": e.get("channel"),
                "security": str(e.get("security", "")),
            }
    return entries, {s for s, _ in entries}


class EvilTwinDetector:
    def __init__(self, cfg, alerts, evidence=None, show_packets=True):
        self.cfg = cfg
        self.alerts = alerts
        self.evidence = evidence
        self.show_packets = show_packets
        self.ignored = {s.lower() for s in (cfg.evil_twin.ignored_ssids or [])}
        self.check_privacy = bool(cfg.evil_twin.alert_on_privacy_change)
        self.alert_unknown = bool(cfg.evil_twin.alert_on_unknown_ap)

        aps_file = getattr(cfg.evil_twin, "allowed_aps_file", "") or ""
        self.allowed, self.allowed_ssids = load_allowed_aps(aps_file)

        self.ssid_bssids = {}  # ssid -> {bssid: profile}
        self.bssid_ssid = {}

    # ------------------------------------------------------------------
    def process(self, pkt):
        dot = pkt.getlayer(Dot11)
        if dot is None or dot.type != 0:
            return
        if dot.subtype not in (8, 5):   # Beacon or Probe Response
            return

        resp = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
        ssid = extract_ssid(pkt)
        if not ssid:
            return      # hidden SSID: cannot compare
        if ssid.lower() in self.ignored:
            return

        bssid = ((dot.addr2 or dot.addr3 or "") or "").lower()
        if not bssid:
            return

        encrypted = bool(resp is not None and (int(resp.cap) & 0x0010))
        label = security_label(resp, pkt)
        channel = extract_beacon_channel(pkt)

        bucket = self.ssid_bssids.setdefault(ssid, {})
        prof = bucket.get(bssid)
        known_ap = (ssid.lower(), bssid) in self.allowed

        if prof is None:
            bucket[bssid] = {"channel": channel, "priv": encrypted,
                             "security": label, "count": 1}
            self.bssid_ssid[bssid] = ssid

            if known_ap:
                if self.show_packets:
                    print(f"    {CYAN}[WLAN]{RESET} legitimate AP seen: {ssid} (BSSID {bssid}, {label})")
                return

            if self.allowed and ssid.lower() in self.allowed_ssids:
                self.alerts.raise_alert(
                    KIND_EVIL_TWIN, "high",
                    "Possible Evil Twin - unregistered BSSID advertising a known SSID!",
                    {
                        "ssid": ssid,
                        "suspicious_bssid": bssid,
                        "other_bssids": self._other_bssids(bucket, bssid),
                        "security": label,
                        "channel": channel,
                    },
                    packet=pkt, evidence=self.evidence,
                    dedupe_key=f"{ssid}|{bssid}",
                )
            elif len(bucket) >= 2:
                self.alerts.raise_alert(
                    KIND_EVIL_TWIN, "high",
                    "Possible Evil Twin - same SSID advertised by two different BSSIDs!",
                    {
                        "ssid": ssid,
                        "new_bssid": bssid,
                        "other_bssids": self._other_bssids(bucket, bssid),
                        "security": label,
                        "channel": channel,
                    },
                    packet=pkt, evidence=self.evidence,
                    dedupe_key=f"{ssid}|{bssid}",
                )
            elif self.allowed and self.alert_unknown:
                self.alerts.raise_alert(
                    KIND_UNKNOWN_AP, "info",
                    "AP unknown to the baseline - review it; can be added manually later",
                    {"ssid": ssid, "bssid": bssid, "security": label},
                    packet=pkt, evidence=self.evidence,
                    dedupe_key=f"{ssid}|{bssid}",
                )
            elif self.show_packets:
                print(f"    {CYAN}[WLAN]{RESET} new AP seen: {ssid} (BSSID {bssid}, {label})")
            return

        # known AP: update counters and check for changes
        prof["count"] += 1
        if self.check_privacy and prof["priv"] != encrypted:
            self.alerts.raise_alert(
                KIND_PRIVACY_CHANGE, "medium",
                "Encryption state changed for the same AP - possible manipulation or rogue AP!",
                {"ssid": ssid, "bssid": bssid,
                 "before": "encrypted" if prof["priv"] else "open",
                 "now": "encrypted" if encrypted else "open"},
                packet=pkt, evidence=self.evidence,
                dedupe_key=f"{ssid}|{bssid}|privacy",
            )
            prof["priv"] = encrypted
        if prof["channel"] and channel and prof["channel"] != channel:
            self.alerts.raise_alert(
                KIND_CHANNEL_CHANGE, "medium",
                "Channel changed for a known AP - review the environment",
                {"ssid": ssid, "bssid": bssid,
                 "before": prof["channel"], "now": channel},
                packet=pkt, evidence=self.evidence,
                dedupe_key=f"{ssid}|{bssid}|chan|{channel}",
            )
            prof["channel"] = channel

    # ------------------------------------------------------------------
    @staticmethod
    def _other_bssids(bucket, bssid):
        return ", ".join(b for b in bucket if b != bssid) or "none"
