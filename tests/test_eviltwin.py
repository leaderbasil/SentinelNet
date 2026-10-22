# -*- coding: utf-8 -*-
"""Unit tests for the Evil Twin detector."""
from ids_tool.config import load_config
from ids_tool.detectors.evil_twin import EvilTwinDetector
from ids_tool.simulator import EVIL_BSSID, GENUINE_BSSID, beacon
from conftest import Recorder

SSID = "Campus-Students-5G"


def _cfg_no_baseline():
    cfg = load_config()
    cfg.evil_twin.allowed_aps_file = ""
    return cfg


def test_single_legitimate_ap_no_alert():
    rec = Recorder()
    det = EvilTwinDetector(_cfg_no_baseline(), rec)   # no baseline -> twin rule only
    det.process(beacon(SSID, GENUINE_BSSID, 6, True))
    det.process(beacon(SSID, GENUINE_BSSID, 6, True))
    assert rec.total_alerts == 0


def test_same_ssid_two_bssids_alerts():
    rec = Recorder()
    det = EvilTwinDetector(_cfg_no_baseline(), rec)
    det.process(beacon(SSID, GENUINE_BSSID, 6, True))
    det.process(beacon(SSID, EVIL_BSSID, 6, False))
    assert rec.kinds.get("EVIL_TWIN", 0) >= 1


def test_baseline_blocks_known_ap_but_flags_twin(tmp_path):
    import yaml
    baseline = tmp_path / "allowed_aps.yaml"
    baseline.write_text(
        yaml.safe_dump([{"ssid": SSID, "bssid": GENUINE_BSSID,
                         "channel": 6, "security": "WPA2/WPA3 (RSN)"}]),
        encoding="utf-8")
    cfg = load_config()
    cfg.evil_twin.allowed_aps_file = str(baseline)
    rec = Recorder()
    det = EvilTwinDetector(cfg, rec)
    det.process(beacon(SSID, GENUINE_BSSID, 6, True))     # known -> silent
    det.process(beacon(SSID, EVIL_BSSID, 6, False))       # twin -> high alert
    kinds = [a["kind"] for a in rec.alerts]
    assert "EVIL_TWIN" in kinds and kinds[0] == "EVIL_TWIN"


def test_unknown_ap_info_alert_with_baseline(tmp_path):
    import yaml
    baseline = tmp_path / "allowed_aps.yaml"
    baseline.write_text(yaml.safe_dump(
        [{"ssid": SSID, "bssid": GENUINE_BSSID}]), encoding="utf-8")
    cfg = load_config()
    cfg.evil_twin.allowed_aps_file = str(baseline)
    rec = Recorder()
    det = EvilTwinDetector(cfg, rec)
    det.process(beacon("SomeOtherNet", "00:11:22:33:44:55", 1, True))
    assert rec.kinds.get("UNKNOWN_AP", 0) >= 1
