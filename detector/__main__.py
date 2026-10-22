# -*- coding: utf-8 -*-
"""
python -m detector : the recommended command-line entry point.

Live capture:
  python -m detector --iface "Wi-Fi" --mode arp
PCAP playback (no capture privileges needed):
  python -m detector --pcap tests/pcaps/attack_scenario.pcap --mode all
Options: --config config.yaml --log-dir ./logs --gateway-ip ... --quiet
"""
from __future__ import annotations

import argparse
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(
        prog="detector",
        description="NetGuard-IDS: network attack detection (monitoring only)",
    )
    ap.add_argument("--iface", help="network interface for live capture")
    ap.add_argument("--pcap", help="PCAP file to replay instead of live capture")
    ap.add_argument("--mode", choices=("arp", "wifi", "all"), default="all",
                    help="wifi == wireless (802.11 frames)")
    ap.add_argument("--config", default=None, help="config file (yaml/json)")
    ap.add_argument("--log-dir", default=None, help="output directory for logs/evidence")
    ap.add_argument("--gateway-ip", default=None)
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not (args.iface or args.pcap):
        ap.print_help()
        return 2

    mode_map = {"arp": "arp", "wifi": "wireless", "all": "all"}
    from ids_tool.sniffer import PacketMonitor

    mon = PacketMonitor(
        iface=args.iface, mode=mode_map[args.mode], timeout=args.timeout,
        config_path=args.config,
        show_packets=not args.quiet, gateway_ip=args.gateway_ip,
        save_evidence=True, log_dir_override=args.log_dir,
        source_pcap=args.pcap,
    )
    try:
        mon.run()
    except KeyboardInterrupt:
        print("\n[stopped by user]")
    finally:
        mon.finalize()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
