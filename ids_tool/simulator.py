# -*- coding: utf-8 -*-
"""
Safe simulation (100% offline).
Builds packets in memory only (never sent on any interface) and feeds them
through the same detection pipeline the live sniffer uses — proving the
detection logic works with zero packets on the wire.

Stages:
 1) normal traffic      -> no alerts
 2) gateway ARP spoof   -> high alert (ARP_SPOOF) + UNSOLICITED_ARP after threshold
 3) ARP flood           -> medium alert (MAC_FLOOD)
 4) Evil Twin           -> high alert (EVIL_TWIN)
 5) Deauth flood        -> high alert (DEAUTH_FLOOD)
 6) unencrypted HTTP    -> info alert (PLAINTEXT_TRAFFIC)
"""
from __future__ import annotations

import time

from scapy.all import ARP, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Ether, RadioTap
from scapy.layers.inet import IP, TCP

from .alerts import GREEN, GREY, MAGENTA, RESET, YELLOW
from .sniffer import PacketMonitor

BROADCAST = "ff:ff:ff:ff:ff:ff"
BOLD_WHITE = "\033[97m"

# lab devices (fictitious, never exist on any interface)
ROUTER_IP, ROUTER_MAC = "192.168.1.1", "aa:bb:cc:00:00:01"
VICTIM_IP, VICTIM_MAC = "192.168.1.50", "aa:bb:cc:00:00:50"
PHONE_IP, PHONE_MAC = "192.168.1.51", "aa:bb:cc:00:00:51"
ATTACKER_IP, ATTACKER_MAC = "192.168.1.66", "aa:bb:cc:00:00:66"

GENUINE_SSID = "Campus-Students-5G"
GENUINE_BSSID = "66:77:88:99:aa:a1"
EVIL_BSSID = "66:77:88:99:aa:b2"
CLIENT_MAC = "11:22:33:44:55:01"

STAGES = []


def stage(title):
    def deco(fn):
        STAGES.append((title, fn))
        return fn
    return deco


def _stage_header(title):
    line = "─" * 64
    print()
    print(f"{MAGENTA}{line}")
    print(f"{BOLD_WHITE}  ▶ {title}{RESET}")
    print(f"{MAGENTA}{line}{RESET}")


def _sleep(d=0.35):
    try:
        time.sleep(d)
    except KeyboardInterrupt:
        pass


# ----------------------------------------------------------------------
# packet builders (in-memory objects only, never sent)
# ----------------------------------------------------------------------
def arp_reply(psrc, hwsrc, pdst, hwdst):
    return (
        Ether(src=hwsrc, dst=hwdst)
        / ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)
    )


def arp_request(psrc, hwsrc, target_ip):
    return (
        Ether(src=hwsrc, dst=BROADCAST)
        / ARP(op=1, psrc=psrc, hwsrc=hwsrc, pdst=target_ip)
    )


def beacon(ssid, bssid, channel=6, encrypted=True):
    cap = 0x0411 if encrypted else 0x0401
    return (
        RadioTap()
        / Dot11(subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=3, info=bytes([channel]))
    )


def deauth_frame(ap_mac, target_mac, reason=7):
    return (
        RadioTap()
        / Dot11(subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
        / Dot11Deauth(reason=reason)
    )


def http_probe(src_ip, dst_ip):
    raw = ("GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n").encode()
    return (
        Ether(src="d8:bb:cc:00:00:50", dst=ROUTER_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=51111, dport=80, flags="PA")
        / raw
    )


# ----------------------------------------------------------------------
# stages
# ----------------------------------------------------------------------
@stage("normal traffic (no attack)")
def stage_normal(mon):
    print("    victim asks for the router; router answers normally...")
    mon.feed(arp_request(VICTIM_IP, VICTIM_MAC, ROUTER_IP))
    mon.feed(arp_reply(ROUTER_IP, ROUTER_MAC, VICTIM_IP, VICTIM_MAC))
    mon.feed(arp_request(PHONE_IP, PHONE_MAC, ROUTER_IP))
    mon.feed(arp_reply(ROUTER_IP, ROUTER_MAC, PHONE_IP, PHONE_MAC))
    print(f"    {GREEN}expectation:{RESET} no alerts - just healthy IP/MAC bindings.")


@stage("gateway + victim ARP spoofing (simulated MITM)")
def stage_arp_mitm(mon):
    print(f"    a rogue device ({ATTACKER_IP}) sends 4 forged replies: "
          f'"{ROUTER_IP} is mine ({ATTACKER_MAC})"')
    for _ in range(4):
        mon.feed(arp_reply(ROUTER_IP, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC))
    n = int(mon.cfg.arp.unsolicited_reply_threshold) + 1
    print(f'    then {n} unsolicited replies: "{VICTIM_IP} is mine" '
          f"(nobody ever asked about that IP on the network)")
    for _ in range(n):
        mon.feed(arp_reply(VICTIM_IP, ATTACKER_MAC, PHONE_IP, PHONE_MAC))
    print(f"    {GREEN}expectation:{RESET} ARP_SPOOF high alerts for both bindings, "
          f"then UNSOLICITED_ARP after {n} replies with no matching request.")


@stage("ARP flood from one MAC")
def stage_mac_flood(mon):
    print("    the same MAC claims 12 different IPs within moments...")
    for i in range(12):
        fake_ip = f"192.168.1.{100 + i}"
        mon.feed(arp_reply(fake_ip, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC))
    print(f"    {GREEN}expectation:{RESET} MAC_FLOOD medium alert after threshold "
          f"({mon.cfg.arp.mac_flood_threshold}).")


@stage("Evil Twin (rogue AP)")
def stage_evil_twin(mon):
    print(f'    genuine AP "{GENUINE_SSID}" (BSSID {GENUINE_BSSID})')
    mon.feed(beacon(GENUINE_SSID, GENUINE_BSSID, 6, encrypted=True))
    _sleep()
    print(f'    then the same name appears from a rogue BSSID ({EVIL_BSSID})...')
    mon.feed(beacon(GENUINE_SSID, EVIL_BSSID, 6, encrypted=False))
    print(f"    {GREEN}expectation:{RESET} EVIL_TWIN high alert (two BSSIDs on one SSID).")


@stage("Deauth flood (forced disconnection)")
def stage_deauth(mon):
    thr = mon.cfg.deauth.alert_threshold
    print(f"    {thr + 1} deauth frames hit client {CLIENT_MAC}, "
          f"spoofing the AP MAC...")
    for _ in range(thr + 1):
        mon.feed(deauth_frame(GENUINE_BSSID, CLIENT_MAC))
    print(f"    {GREEN}expectation:{RESET} DEAUTH_FLOOD high alert after threshold {thr} "
          f"in {mon.cfg.deauth.window_seconds:.0f}s.")


@stage("unencrypted HTTP traffic - sniffing exposure")
def stage_http(mon):
    print("    a device opens a plain HTTP site...")
    mon.feed(http_probe(VICTIM_IP, "93.184.216.34"))
    print(f"    {GREEN}expectation:{RESET} PLAINTEXT_TRAFFIC info alert - "
          "data is interceptable by a passive sniffer.")


# ----------------------------------------------------------------------
def run_simulation(show_packets=True, config_path=None, quiet=False):
    print()
    print("=" * 64)
    print(BOLD_WHITE + "  SAFE SIMULATION - zero packets sent on any network interface" + RESET)
    print("  (packets are built in memory and fed to the detection pipeline)")
    print("=" * 64)
    print("  lab devices:")
    print(f"   router/gateway : {ROUTER_IP:15} {ROUTER_MAC}")
    print(f"   victim laptop  : {VICTIM_IP:15} {VICTIM_MAC}")
    print(f"   victim phone   : {PHONE_IP:15} {PHONE_MAC}")
    print(f"   attacker       : {ATTACKER_IP:15} {ATTACKER_MAC}")
    print("=" * 64)

    mon = PacketMonitor(mode="all", config_path=config_path,
                        show_packets=show_packets, gateway_ip=ROUTER_IP,
                        save_evidence=False)

    total = len(STAGES)
    for i, (title, fn) in enumerate(STAGES, start=1):
        _stage_header(f"[{i}/{total}] {title}")
        fn(mon)
        _sleep()

    print()
    print("=" * 64)
    print(f"{BOLD_WHITE}  SIMULATION RESULT{RESET}")
    print("=" * 64)
    for kind in ("ARP_SPOOF", "UNSOLICITED_ARP", "MAC_FLOOD", "EVIL_TWIN",
                 "DEAUTH_FLOOD", "PLAINTEXT_TRAFFIC"):
        n = mon.alerts.kinds.get(kind, 0)
        mark = f"{GREEN}✅ detected{RESET}" if n else f"{GREY}⚪ silent{RESET}"
        print(f"   {mark}  {kind:20} {YELLOW}{n} alert(s){RESET}")
    print(f"{GREY}   total packets inspected: {mon.total}  (never sent, in memory only){RESET}")

    mon.finalize()
    return {
        "packets": mon.total,
        "alerts": dict(mon.alerts.kinds),
        "total_alerts": mon.alerts.total_alerts,
    }
