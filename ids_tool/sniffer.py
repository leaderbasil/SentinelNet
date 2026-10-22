# -*- coding: utf-8 -*-
"""
Capture & analysis engine (PacketMonitor):
- Captures live packets via Scapy sniff, OR replays a PCAP file (test mode).
- Dispatches each packet to the detectors (ARP / Deauth / Evil Twin).
- In "all" mode also flags unencrypted HTTP traffic (sniffing exposure).
Console text is English for clarity; Arabic documentation lives in docs/.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from scapy.all import Dot11, ARP, sniff
from scapy.layers.inet import TCP

from .alerts import AlertManager, BOLD, CYAN, GREEN, GREY, RESET, YELLOW

from .config import PROJECT_ROOT, load_config
from .detectors.arp_spoofing import ARPSpoofingDetector
from .detectors.deauth import DeauthDetector
from .detectors.evil_twin import EvilTwinDetector
from .evidence import EvidenceStore

MODES = ("arp", "wireless", "all")

MODE_TEXT = {
    "arp": "ARP traffic (MITM detection)",
    "wireless": "802.11 frames (Deauth / Evil Twin detection)",
    "all": "everything (full detection + HTTP exposure hints)",
}


class PacketMonitor:
    def __init__(self, iface=None, mode="arp", timeout=None, config_path=None,
                 show_packets=True, gateway_ip=None, save_evidence=True,
                 log_dir_override=None, source_pcap=None):
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}. allowed: {MODES}")
        self.cfg = load_config(config_path)
        self.mode = mode
        self.iface = iface
        self.timeout = timeout
        self.show_packets = show_packets
        self.source_pcap = source_pcap

        # logs/evidence directory
        log_dir = Path(log_dir_override) if log_dir_override else (PROJECT_ROOT / str(self.cfg.logging.dir))
        log_dir.mkdir(parents=True, exist_ok=True)
        self._log_dir = log_dir
        tag = datetime.now().strftime("%Y%m%d_%H%M%S")

        # alerts (JSONL evidence file)
        self.alert_log = None
        if self.cfg.logging.save_alerts_jsonl:
            self.alert_log = log_dir / f"alerts_{tag}.jsonl"
        self.alerts = AlertManager(self.cfg, log_file=self.alert_log)

        # evidence store (PCAP) - only for single-interface captures
        self.evidence = None
        if save_evidence and self.cfg.logging.save_evidence_pcap:
            self.evidence = EvidenceStore(self.cfg, log_dir, tag)

        # detectors
        self.arp_d = ARPSpoofingDetector(
            self.cfg, self.alerts, evidence=self.evidence,
            show_packets=show_packets, gateway_ip=gateway_ip,
        )
        self.deauth_d = DeauthDetector(
            self.cfg, self.alerts, evidence=self.evidence, show_packets=show_packets,
        )
        self.twin_d = EvilTwinDetector(
            self.cfg, self.alerts, evidence=self.evidence, show_packets=show_packets,
        )

        self.total = 0
        self.errors = 0
        self._http_last = 0.0

        # soft note: if a restricted interface list is configured, mention it
        allowed = list(getattr(self.cfg.guard, "allowed_interfaces", None) or [])
        if allowed and iface and not any(str(i).lower() in str(iface).lower() or
                                         str(iface).lower() == str(i).lower() for i in allowed):
            print(f"{YELLOW}[note]{RESET} interface not in guard.allowed_interfaces list "
                  f"(monitoring allowed; lab traffic generators would refuse it).")

    # ------------------------------------------------------------------
    def feed(self, pkt):
        """Process a single packet (used by capture and by the simulator)."""
        self.total += 1
        try:
            self._dispatch(pkt)
        except Exception as e:
            self.errors += 1
            print(f"{GREY}[warn] packet analysis failed: {e!r}{RESET}")

    def _dispatch(self, pkt):
        # 1) ARP
        if pkt.haslayer(ARP):
            if self.mode != "wireless":
                self.arp_d.process(pkt)

        # 2) 802.11
        if pkt.haslayer(Dot11):
            if self.mode != "arp":
                self.deauth_d.process(pkt)
                self.twin_d.process(pkt)

        # 3) HTTP exposure hint
        if self.mode == "all":
            try:
                if pkt.haslayer(TCP) and int(pkt[TCP].dport) == 80:
                    now = time.time()
                    if now - self._http_last >= 30.0:
                        self._http_last = now
                        ip = "?"
                        try:
                            ip = pkt.getlayer("IP").src
                        except Exception:
                            pass
                        self.alerts.raise_alert(
                            "PLAINTEXT_TRAFFIC", "info",
                            "Unencrypted HTTP traffic on port 80 - sniffable",
                            {"source": ip,
                             "safer": "use HTTPS / DNS-over-HTTPS / VPN"},
                            packet=pkt, evidence=self.evidence,
                            dedupe_key="http",
                        )
            except Exception:
                pass

    # ------------------------------------------------------------------
    def run(self):
        """Live capture or PCAP replay depending on the source."""
        if self.source_pcap:
            self._replay_pcap()
        else:
            self.start()

    def _replay_pcap(self):
        from scapy.utils import PcapReader
        print(f"{GREEN}[running]{RESET} reading PCAP file: {BOLD}{self.source_pcap}{RESET}")
        try:
            with PcapReader(str(self.source_pcap)) as rd:
                for pkt in rd:
                    try:
                        self.feed(pkt)
                    except KeyboardInterrupt:
                        raise
        except FileNotFoundError:
            print(f"{YELLOW}[!] PCAP file not found: {self.source_pcap}{RESET}")
            return
        except PermissionError as e:
            print(f"{YELLOW}[!] cannot read PCAP file: {e}{RESET}")
            return

    def start(self):
        kwargs = dict(prn=self.feed, store=False, verbose=0)
        if self.iface:
            kwargs["iface"] = self.iface

        if self.mode == "arp":
            kwargs["lfilter"] = lambda p: p.haslayer(ARP)
        elif self.mode == "wireless":
            kwargs["lfilter"] = lambda p: p.haslayer(Dot11)

        if self.show_packets:
            print(f"{GREEN}[running]{RESET} mode: {BOLD}{self.source_pcap and '' or (MODE_TEXT[self.mode])}{BOLD}{RESET}"
                  f" | iface: {self.iface or 'default'} | Ctrl+C to stop\n")

        try:
            sniff(**kwargs)
        except PermissionError as e:
            print(f"{YELLOW}[!] insufficient permissions for capture: {e}{RESET}")
            print("    Windows: run terminal as Administrator. Linux: sudo.")
        except Exception as e:
            if any(x in str(e).lower() for x in ("libpcap", "npf", "pcap")):
                print(f"{YELLOW}[!] capture unavailable:{RESET} {e}")
                print("    Windows: install Npcap from https://npcap.com and rerun.")
                print("    Linux: ensure libpcap; wireless needs monitor-mode iface.")
            else:
                raise

    def finalize(self):
        """Saves evidence and prints the session summary."""
        pcap = self.evidence.save() if self.evidence else None
        manifest = self._save_manifest(pcap)
        print("\n" + "=" * 60)
        print(f"{BOLD}📋 Session summary{RESET}")
        print("=" * 60)
        print(f" packets inspected : {BOLD}{self.total}{RESET}")
        print(f" analysis errors   : {BOLD}{self.errors}{RESET}")
        print(f" total alerts      : {BOLD}{YELLOW}{self.alerts.total_alerts}{RESET}")
        for kind, count in sorted(self.alerts.kinds.items()):
            print(f"    {YELLOW}• {kind:22} {BOLD}{count}{RESET}")
        if self.alert_log:
            print(f" {GREEN}alerts log (JSONL){RESET}   : {self.alert_log}")
        if pcap:
            print(f" {GREEN}evidence (PCAP){RESET}     : {pcap}")
            print(f"   open it in Wireshark to inspect the suspicious packets.")
        if manifest:
            print(f" {GREEN}evidence manifest{RESET}   : {manifest}   (verify with: python tools/verify.py)")
        if not pcap and not self.alert_log:
            print(f" {GREY}nothing suspicious recorded.{RESET}")

    def _save_manifest(self, pcap):
        """SHA-256 manifest for the session evidence files."""
        from .evidence import sha256_file
        entries = []
        for path in ([self.alert_log, pcap] if pcap else [self.alert_log]):
            try:
                if path and Path(path).exists():
                    entries.append({
                        "file": str(path),
                        "sha256": sha256_file(path),
                        "bytes": Path(path).stat().st_size,
                    })
            except Exception:
                pass
        if not entries:
            return None
        manifest = self._log_dir / f"manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import json
        manifest.write_text(json.dumps(
            {"generated": datetime.now().isoformat(timespec="seconds"),
             "files": entries}, ensure_ascii=False, indent=2), encoding="utf-8")
        return manifest

    # backwards-compatible alias
    def stop_and_summarize(self):
        self.finalize()
