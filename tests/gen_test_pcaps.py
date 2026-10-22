# -*- coding: utf-8 -*-
"""
Generates two synthetic test PCAPs (never sent on any interface):
  tests/pcaps/arp_scan.pcap    -> Ethernet frames (ARP attacks + HTTP)
  tests/pcaps/wifi_scan.pcap   -> 802.11 frames (Beacons + Deauth flood)
Files are separated by linktype so every packet parses correctly.

Replay them (no capture privileges needed):
  python -m detector --pcap tests/pcaps/arp_scan.pcap  --mode all
  python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.utils import wrpcap

from ids_tool.simulator import (
    ATTACKER_MAC, CLIENT_MAC, EVIL_BSSID, GENUINE_BSSID, GENUINE_SSID,
    PHONE_IP, PHONE_MAC, ROUTER_IP, ROUTER_MAC, VICTIM_IP, VICTIM_MAC,
    arp_reply, arp_request, beacon, deauth_frame, http_probe,
)


def build_arp() -> list:
    pkts = []
    # normal traffic
    pkts.append(arp_request(VICTIM_IP, VICTIM_MAC, ROUTER_IP))
    pkts.append(arp_reply(ROUTER_IP, ROUTER_MAC, VICTIM_IP, VICTIM_MAC))
    pkts.append(arp_request(PHONE_IP, PHONE_MAC, ROUTER_IP))
    pkts.append(arp_reply(ROUTER_IP, ROUTER_MAC, PHONE_IP, PHONE_MAC))
    # gateway spoof
    for _ in range(4):
        pkts.append(arp_reply(ROUTER_IP, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC))
    # unsolicited victim-IP replies
    for _ in range(7):
        pkts.append(arp_reply(VICTIM_IP, ATTACKER_MAC, PHONE_IP, PHONE_MAC))
    # ARP flood from one MAC
    for i in range(12):
        pkts.append(arp_reply(f"192.168.1.{100 + i}", ATTACKER_MAC,
                              VICTIM_IP, VICTIM_MAC))
    # plaintext HTTP
    pkts.append(http_probe(VICTIM_IP, "93.184.216.34"))
    return pkts


def build_wifi() -> list:
    pkts = []
    # legitimate AP + rogue twin (same SSID)
    pkts.append(beacon(GENUINE_SSID, GENUINE_BSSID, 6, encrypted=True))
    pkts.append(beacon(GENUINE_SSID, EVIL_BSSID, 6, encrypted=False))
    # deauth flood (reason 7)
    for _ in range(11):
        pkts.append(deauth_frame(GENUINE_BSSID, CLIENT_MAC))
    return pkts


def main():
    out_dir = Path(__file__).resolve().parent / "pcaps"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, pkts in (("arp_scan.pcap", build_arp()),
                       ("wifi_scan.pcap", build_wifi())):
        out = out_dir / name
        wrpcap(str(out), pkts)
        print(f"written: {out}  ({len(pkts)} packets)")
    print("next:")
    print("  python -m detector --pcap tests/pcaps/arp_scan.pcap  --mode all")
    print("  python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all")


if __name__ == "__main__":
    main()
