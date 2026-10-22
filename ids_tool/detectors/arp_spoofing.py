# -*- coding: utf-8 -*-
"""
ARP spoofing detector (indicates a MITM attack).
Rules (no blind alert on every ARP reply - avoids false positives):
1) IP<->MAC binding change (higher risk if the IP is the gateway).
2) One MAC claiming many IPs (ARP flood / aggressive scan).
3) Unsolicited ARP replies above threshold in a time window.
+ Whitelist of trusted bindings (pins the gateway from the first moment).
"""
from __future__ import annotations

import time
from collections import deque

from ..alerts import GREEN, RESET

KIND_ARP_SPOOF = "ARP_SPOOF"
KIND_MAC_FLOOD = "MAC_FLOOD"
KIND_UNSOLICITED = "UNSOLICITED_ARP"


def _norm_mac(m):
    return (m or "").strip().lower()


def get_default_gateway():
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0/0")[2]
        if gw and gw not in ("0.0.0.0", None):
            return gw
    except Exception:
        pass
    return None


class ARPSpoofingDetector:
    def __init__(self, cfg, alerts, evidence=None, show_packets=True, gateway_ip=None):
        self.cfg = cfg
        self.alerts = alerts
        self.evidence = evidence
        self.show_packets = show_packets

        self.whitelist = []
        for e in (getattr(cfg.arp, "whitelist", None) or []):
            try:
                self.whitelist.append((str(e.get("ip", "")).lower(), _norm_mac(e.get("mac"))))
            except AttributeError:
                pass

        # state table: pinned trusted bindings come from the whitelist
        self.ip_mac = {ip: mac for ip, mac in self.whitelist}
        self.mac_ips = {}
        self.gateway_ip = gateway_ip or get_default_gateway()

        self.unsolicited_window = float(cfg.arp.unsolicited_window_seconds)
        self.unsolicited_threshold = int(cfg.arp.unsolicited_reply_threshold)
        self._requests = {}      # requested ip -> last request time
        self._unsolicited = {}   # (ip, mac) -> timestamps
        self.flood_threshold = int(cfg.arp.mac_flood_threshold)

    # ------------------------------------------------------------------
    def _is_whitelisted(self, ip, mac):
        return ((ip or "").lower(), _norm_mac(mac)) in self.whitelist

    def process(self, pkt):
        arp = pkt.getlayer("ARP")
        if arp is None:
            return
        ip, mac = arp.psrc, _norm_mac(arp.hwsrc)
        if not ip or not mac:
            return
        if ip == "0.0.0.0" or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        now = time.time()
        if int(arp.op) == 1:
            if arp.pdst:
                self._requests[str(arp.pdst).lower()] = now
            self._record(ip, mac, arp, pkt, now)
            return

        self._record(ip, mac, arp, pkt, now)
        if not self._is_whitelisted(ip, mac):
            self._check_unsolicited(ip, mac, now, pkt)

    # ------------------------------------------------------------------
    def _record(self, ip, mac, arp, pkt, now):
        last = self.ip_mac.get(ip)
        is_new = ip not in self.ip_mac

        # Rule 1: binding conflict
        if last and last != mac and not self._is_whitelisted(ip, mac) \
                and not self._is_whitelisted(ip, last):
            details = {
                "ip": ip,
                "old_mac": last,
                "new_mac": mac,
                "frame": "ARP reply (is-at)" if int(arp.op) == 2 else f"op={arp.op}",
            }
            title = "Possible ARP Spoofing / MITM attack!"
            if self.gateway_ip and ip == self.gateway_ip:
                details["extra_risk"] = (
                    f"This IP is the DEFAULT GATEWAY (router): someone now claims to be it!"
                )
                title = "Possible MITM attack: a device is impersonating the default gateway (router)!"
            self.alerts.raise_alert(
                KIND_ARP_SPOOF, "high", title, details,
                packet=pkt, evidence=self.evidence,
                dedupe_key=f"{ip}|{last}|{mac}",
            )

        if is_new:
            self.ip_mac[ip] = mac
            if self.show_packets:
                note = " (gateway/router)" if (self.gateway_ip and ip == self.gateway_ip) else ""
                print(f"    {GREEN}[ARP]{RESET} new device on network: {ip} -> {mac}{note}")

        # Rule 2: one MAC claiming many IPs
        claimed = self.mac_ips.setdefault(mac, set())
        claimed.add(ip)
        if len(claimed) > self.flood_threshold:
            self.alerts.raise_alert(
                KIND_MAC_FLOOD, "medium",
                "One MAC claiming multiple IPs - possible ARP flood / aggressive scan!",
                {"mac": mac, "claimed_ip_count": len(claimed),
                 "examples": ", ".join(sorted(claimed)[:5])},
                packet=pkt, evidence=self.evidence, dedupe_key=f"{mac}",
            )

    # ------------------------------------------------------------------
    def _check_unsolicited(self, ip, mac, now, pkt):
        """Reply with no recent matching request."""
        last_req = self._requests.get((ip or "").lower(), 0)
        if last_req and (now - last_req) <= self.unsolicited_window:
            return
        key = ((ip or "").lower(), mac)
        q = self._unsolicited.setdefault(key, deque())
        q.append(now)
        while q and (now - q[0]) > self.unsolicited_window:
            q.popleft()
        if len(q) >= self.unsolicited_threshold:
            self.alerts.raise_alert(
                KIND_UNSOLICITED, "medium",
                "High rate of unsolicited ARP replies - possible ARP poisoning!",
                {"ip": ip, "sender_mac": mac,
                 "reply_count": len(q),
                 "window": f"{self.unsolicited_window:.0f}s"},
                packet=pkt, evidence=self.evidence,
                dedupe_key=f"{ip}|{mac}|{int(now // self.unsolicited_window)}",
            )
