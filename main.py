# -*- coding: utf-8 -*-
"""
NetGuard-IDS - network attack detector tool (Scapy)
Monitoring/detection only. Commands:
  python main.py list-ifaces               list network interfaces
  python main.py sniff --mode arp          live ARP capture (MITM detection)
  python main.py sniff --mode wireless     802.11 frames (Deauth/Evil Twin)
  python main.py sniff --mode all          everything + HTTP exposure hints
  python main.py simulate                  fully-safe offline demo (proves detection)
  python main.py selftest                  quick module self-test
PCAP playback (recommended test path):
  python tests/gen_test_pcaps.py
  python -m detector --pcap tests/pcaps/attack_scenario.pcap --mode all
"""
from __future__ import annotations

import argparse
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BANNER = r"""
================================================================
   NetGuard-IDS - Scapy Network Attack Detector
   Detection tool: monitors traffic, raises alerts, keeps evidence.
================================================================
"""


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="NetGuard-IDS",
        description="Network attack detection tool (monitoring only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    p_sniff = sub.add_parser("sniff", help="capture real traffic and detect attacks")
    p_sniff.add_argument("--iface", help="network interface name (from list-ifaces)")
    p_sniff.add_argument("--mode", choices=("arp", "wireless", "all"), default="arp")
    p_sniff.add_argument("--timeout", type=float, default=None,
                         help="capture duration in seconds (optional)")
    p_sniff.add_argument("--quiet", action="store_true",
                         help="hide per-packet lines, show alerts only")
    p_sniff.add_argument("--gateway-ip", default=None,
                         help="override auto-detection of the gateway IP")

    sub.add_parser("simulate", help="100%-safe offline demo of the detector")
    sub.add_parser("selftest", help="quick self-test of every detector module")
    sub.add_parser("list-ifaces", help="show available network interfaces")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 0

    if args.cmd == "list-ifaces":
        from scapy.all import conf
        try:
            conf.ifaces.show()
        except Exception:
            from scapy.all import get_if_list
            for i in get_if_list():
                print(" -", i)
        return 0

    if args.cmd == "simulate":
        from ids_tool.simulator import run_simulation
        run_simulation(show_packets=True)
        print("next: try live capture with  python main.py sniff --mode arp\n")
        return 0

    if args.cmd == "selftest":
        from ids_tool.alerts import GREEN, RED, RESET
        from ids_tool.simulator import run_simulation
        stats = run_simulation(show_packets=False)
        a = stats["alerts"]
        checks = [
            ("ARP_SPOOF", a.get("ARP_SPOOF", 0) >= 1),
            ("UNSOLICITED_ARP", a.get("UNSOLICITED_ARP", 0) >= 1),
            ("MAC_FLOOD", a.get("MAC_FLOOD", 0) >= 1),
            ("EVIL_TWIN", a.get("EVIL_TWIN", 0) >= 1),
            ("DEAUTH_FLOOD", a.get("DEAUTH_FLOOD", 0) >= 1),
            ("PLAINTEXT_TRAFFIC", a.get("PLAINTEXT_TRAFFIC", 0) >= 1),
        ]
        print()
        ok = True
        for name, passed in checks:
            mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
            print(f" {mark} - detector {name}")
            ok &= passed
        print()
        if ok:
            print(f"{GREEN}======================================")
            print("  All detectors work - project ready to demo")
            print(f"======================================{RESET}\n")
            return 0
        return 1

    # --- sniff ---
    if args.mode in ("wireless", "all"):
        print("note: wireless mode needs a monitor-mode interface "
              "(Linux / a capable USB adapter); on Windows use wired --mode arp "
              "or a PCAP file instead.\n")
    from ids_tool.sniffer import PacketMonitor
    mon = PacketMonitor(iface=args.iface, mode=args.mode, timeout=args.timeout,
                        show_packets=not args.quiet, gateway_ip=args.gateway_ip)
    try:
        mon.start()
    except KeyboardInterrupt:
        print("\n[stopped by user (Ctrl+C)]")
    finally:
        mon.finalize()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
