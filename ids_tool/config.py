# -*- coding: utf-8 -*-
"""
إعدادات NetGuard-IDS: تُقرأ من config.yaml (أو config.json كخيار سابق)
مع قيم افتراضية (DEFAULTS). لا قيم ثابتة داخل الكود.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]

try:
    import yaml
except ImportError:
    yaml = None

DEFAULTS = {
    "arp": {
        # عدد عناوين IP التي يدّعيها نفس MAC قبل تنبيه الفيض
        "mac_flood_threshold": 10,
        # ردود ARP بلا طلب سابق: عتبة ونافذة
        "unsolicited_reply_threshold": 6,
        "unsolicited_window_seconds": 10.0,
        # روابط شرعية معروفة: تُثبّت من البداية وتُتجاهل في التنبيهات
        "whitelist": [],   # [{ip: 192.168.1.1, mac: aa:bb:cc:...}]
    },
    "deauth": {
        # عتبة الإطارات خلال النافذة (تضبط بالتجربة)
        "alert_threshold": 10,
        "window_seconds": 10.0,
    },
    "evil_twin": {
        # ملف خط أساس النقاط الشرعية (مسار نسبي لجذر المشروع)
        "allowed_aps_file": "lab/allowed_aps.yaml",
        "ignored_ssids": [],
        "alert_on_privacy_change": True,
        "alert_on_unknown_ap": True,
    },
    "alerts": {
        "cooldown_seconds": 15.0,
    },
    "logging": {
        "dir": "logs",
        "save_alerts_jsonl": True,
        "save_evidence_pcap": True,
        "evidence_max_packets": 500,
    },
    # ضوابط السلامة (إلزامية) — راجع docs/PROJECT_PLAN.txt القسم 8
    "guard": {
        # فارغة = الالتقاط من أي واجهة مسموح. مولدات المختبر تتوقف إذا لم تكن الواجهة هنا
        "allowed_interfaces": [],
        # الحد الأقصى لحزم مولدات الحركة الاختبارية لكل تشغيل
        "lab_traffic_limit": 50,
        # مولدات الهجمات ممنوعة إذا كان للجهاز اتصال إنترنت
        "require_isolated_link": True,
    },
}


def _merge(base, override):
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _to_ns(d):
    return SimpleNamespace(**{k: _to_ns(v) if isinstance(v, dict) else v
                              for k, v in d.items()})


def _resolve_user_config(explicit=None):
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise SystemExit(f"ملف الإعدادات غير موجود: {p}")
        return p
    for name in ("config.yaml", "config.yml", "config.json"):
        p = PROJECT_ROOT / name
        if p.exists():
            return p
    return None


def load_config(path=None):
    p = _resolve_user_config(path)
    user = {}
    if p:
        if p.suffix.lower() in (".yaml", ".yml"):
            if yaml is None:
                raise SystemExit("مطلوب مكتبة PyYAML:  python -m pip install pyyaml")
            user = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        else:
            user = json.loads(p.read_text(encoding="utf-8"))
    return _to_ns(_merge(DEFAULTS, user))
