# -*- coding: utf-8 -*-
"""Unit tests for the Deauth flood detector."""
from ids_tool.config import load_config
from ids_tool.detectors.deauth import DeauthDetector
from ids_tool.simulator import CLIENT_MAC, EVIL_BSSID, GENUINE_BSSID, beacon, deauth_frame
from conftest import Recorder


def test_clean_beacons_no_alert():
    rec = Recorder()
    det = DeauthDetector(load_config(), rec)
    for _ in range(30):
        det.process(beacon("Campus-Students-5G", GENUINE_BSSID, 6, True))
    assert rec.total_alerts == 0


def test_few_deauth_frames_no_alert():
    rec = Recorder()
    det = DeauthDetector(load_config(), rec)
    for _ in range(max(1, det.threshold - 2)):
        det.process(deauth_frame(GENUINE_BSSID, CLIENT_MAC))
    assert rec.total_alerts == 0


def test_deauth_flood_alerts_with_reason():
    rec = Recorder()
    det = DeauthDetector(load_config(), rec)
    n = det.threshold
    for _ in range(n):
        det.process(deauth_frame(GENUINE_BSSID, CLIENT_MAC, reason=7))
    assert rec.kinds.get("DEAUTH_FLOOD", 0) >= 1
    alert = next(a for a in rec.alerts if a["kind"] == "DEAUTH_FLOOD")
    assert alert["details"]["reason_code"] == 7


def test_separate_pairs_counted_independently():
    rec = Recorder()
    det = DeauthDetector(load_config(), rec)
    for _ in range(max(1, det.threshold - 2)):
        det.process(deauth_frame(GENUINE_BSSID, CLIENT_MAC))
        det.process(deauth_frame(EVIL_BSSID, CLIENT_MAC))
    assert rec.total_alerts == 0  # below threshold for each pair
