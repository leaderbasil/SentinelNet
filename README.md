# NetGuard-IDS — Network Attack Detector Using Scapy

A **defensive** tool: detects network attacks, raises alerts, and keeps evidence — it does **not** perform any attack.

| Attack | How the tool alerts you |
|---|---|
| MITM via ARP Spoofing | IP↔MAC mapping change (especially the gateway) / replies nobody asked for |
| Deauth (forced disconnection) | High rate of deauth frames within a short time window |
| Evil Twin | Unapproved BSSID advertising a legitimate SSID (baseline check), or the same SSID from a different BSSID |
| Sniffing risks | Interceptable unencrypted HTTP traffic (advisory) |
| Access attempts | Unencrypted HTTP alert or firewall blocking (per supervisor's exercise logic) |

---

## 1) Installation

```powershell
cd "Desktop\scopy scan"
python -m pip install -r requirements.txt   # scapy, colorama, pyyaml, pytest
python main.py selftest                     # expect: PASS for all six detectors
```

## 2) Running

### a) Safe simulation (for the demo — zero packets on the network)
```powershell
python main.py simulate
```

### b) Reading PCAP files (no privileges, same engine as live capture)
```powershell
python tests/gen_test_pcaps.py                       # generate synthetic test files
python -m detector --pcap tests/pcaps/arp_scan.pcap  --mode all
python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all
```

### c) Live capture (needs Npcap on Windows + administrator privileges)
```powershell
python main.py list-ifaces
python -m detector --iface "Wi-Fi" --mode arp         # MITM via ARP
python -m detector --iface <iface> --mode wifi        # needs monitor mode (Linux)
python -m detector --iface "Ethernet" --mode all --log-dir ./logs
```

## 3) Alerts and evidence
- `logs/alerts_*.jsonl` — every alert (time, type, severity, details).
- `logs/evidence_*.pcap` — the suspicious packets (open in Wireshark).
- `logs/manifest_*.json` — SHA-256 fingerprint of each evidence file; verify with:
```powershell
python tools/verify.py logs
```

## 4) Configuration (config.yaml)
Each detector's thresholds (ARP flood, Deauth window, etc.) — no hardcoded values in code. Key settings:
- `arp.whitelist`: legitimate bindings pinned at startup (e.g. the gateway).
- `evil_twin.allowed_aps_file`: baseline of legitimate APs, `lab/allowed_aps.yaml`.
- `guard`: lab safety controls (interface list, 50-packet cap, internet check).

## 5) Tests (pytest — no live attacks)
```powershell
python -m pytest tests/test_arp.py tests/test_deauth.py tests/test_eviltwin.py -q
python -m pytest -q        # or everything
```
Each detector has: an alert case + a benign case that must stay silent (12 tests currently, all passing).

## 6) Campus lab (in a VM — Linux)
See `lab/README.md`: the two cases A/B (`setup_baseline.sh` / `setup_hardened.sh`),
hostapd configs (WPA3-SAE + PMF), nftables rules, and mac80211_hwsim wireless
simulation — with the PCAP-replay alternative plan (easier, for demonstrating detections in reports).

## 7) Legal framework
Monitoring tool only. Test on your own lab or with written permission. The actual
spoofing script (`tests/lab_spoof_sim.py`) is locked behind safety controls — it
refuses to run on a network with internet access or an interface not listed in
`guard.allowed_interfaces`.

## 8) AI usage disclosure
An AI assistant was used to help write the code and documentation in this
repository (disclosed per section 8 of the official document). Final review,
verification, and execution were done by the student.

## 9) Repository structure
```
main.py                        entry point (sniff/simulate/selftest/list-ifaces)
detector/__main__.py           python -m detector --iface/--pcap
config.yaml                    thresholds and lists (no hardcoded values)
ids_tool/
  sniffer.py                   engine (live capture or PCAP replay)
  alerts.py                    alerts (console + JSONL)
  evidence.py                  evidence + SHA-256
  guard.py                     safety controls (section 8)
  simulator.py                 demo simulation
  detectors/arp_spoofing.py    MITM via ARP (mapping change, flood, unsolicited replies)
  detectors/deauth.py          forced disconnection (per station pair + reason code)
  detectors/evil_twin.py       rogue AP (baseline + RSN + channel/encryption)
  detectors/...                ...
tests/                         pytest (12) + test PCAP files
tools/verify.py                evidence integrity check (SHA-256)
lab/                           A/B case templates + hostapd + nftables + baseline
docs/                          report: theory + results table + plan
```
