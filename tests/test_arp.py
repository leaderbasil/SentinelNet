# -*- coding: utf-8 -*-
"""Unit tests for the ARP spoofing detector (no live network traffic)."""
from ids_tool.config import load_config
from ids_tool.detectors.arp_spoofing import ARPSpoofingDetector
from ids_tool.simulator import (
    ATTACKER_MAC, PHONE_MAC, PHONE_IP, ROUTER_IP, ROUTER_MAC,
    VICTIM_IP, VICTIM_MAC, arp_reply, arp_request,
)
from conftest import Recorder

GW = ROUTER_IP
GW_MAC = ROUTER_MAC


def make_detector(rec=None, cfg=None):
    cfg = cfg or load_config()
    return ARPSpoofingDetector(cfg, rec or Recorder(), gateway_ip=GW)


def test_healthy_binding_changes_no_alert():
    rec = Recorder()
    det = make_detector(rec)
    det.process(arp_request(VICTIM_IP, VICTIM_MAC, GW))
    det.process(arp_reply(GW, GW_MAC, VICTIM_IP, VICTIM_MAC))
    det.process(arp_reply(GW, GW_MAC, PHONE_IP, PHONE_MAC))
    assert rec.total_alerts == 0


def test_gateway_spoofing_alerts():
    rec = Recorder()
    det = make_detector(rec)
    det.process(arp_reply(GW, GW_MAC, VICTIM_IP, VICTIM_MAC))
    det.process(arp_reply(GW, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC))
    kinds = [a["kind"] for a in rec.alerts]
    assert "ARP_SPOOF" in kinds


def test_unsolicited_replies_alert():
    rec = Recorder()
    det = make_detector(rec)
    thr = det.unsolicited_threshold
    for _ in range(thr + 1):
        det.process(arp_reply(VICTIM_IP, ATTACKER_MAC, PHONE_IP, PHONE_MAC))
    assert "UNSOLICITED_ARP" in rec.kinds


def test_whitelist_pins_gateway():
    rec = Recorder()
    cfg = load_config()
    cfg.arp.whitelist = [{"ip": GW, "mac": GW_MAC}]
    det = ARPSpoofingDetector(cfg, rec, gateway_ip=GW)
    det.process(arp_reply(GW, GW_MAC, VICTIM_IP, VICTIM_MAC))
    det.process(arp_reply(GW, GW_MAC, PHONE_IP, PHONE_MAC))
    assert rec.total_alerts == 0
