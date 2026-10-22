# -*- coding: utf-8 -*-
"""
ضوابط السلامة (إلزامية) — تطبق اشتراطات الوثيقة الرسمية للمشروع:
1) مولدات الحركة الاختبارية لا تعمل إلا على واجهات مسجلة في config.yaml.
2) تتوقف فورًا إذا اكتشفت اتصالًا بالإنترنت على الجهاز.
3) حد أقصى صغير للحزم لكل تشغيل (lab_traffic_limit، الافتراضي 50).
"""
from __future__ import annotations

import socket


def iface_allowed(iface, cfg) -> bool:
    allowed = list(getattr(cfg.guard, "allowed_interfaces", None) or [])
    if not allowed:
        return True
    if not iface:
        return False
    name = str(iface).strip().lower()
    return any(name == a.lower() or a.lower() in name for a in allowed)


def require_lab_interface(iface, cfg):
    """للمولدات: توقف إذا لم تكن الواجهة مسجلة."""
    if not iface_allowed(iface, cfg):
        raise SystemExit(
            "⛔ ضوابط المختبر: الواجهة غير مسجلة في config.yaml (guard.allowed_interfaces).\n"
            "   سجّل أسماء واجهات المختبر المعزول فقط ثم أعد التشغيل."
        )


def internet_reachable(timeout=2.0) -> bool:
    for probe in (("8.8.8.8", 53), ("1.1.1.1", 53)):
        try:
            with socket.create_connection(probe, timeout=timeout):
                return True
        except OSError:
            continue
    return False


def require_isolated_network(cfg):
    """للمولدات: توقف إذا كان الجهاز متصلًا بالإنترنت."""
    if getattr(cfg.guard, "require_isolated_link", True) and internet_reachable():
        raise SystemExit(
            "⛔ ضوابط المختبر: ثمة اتصال بالإنترنت على هذا الجهاز.\n"
            "   مولدات الهجمات تُشغَّل فقط داخل شبكة معزولة (بدون إنترنت)."
        )


def traffic_limit(cfg) -> int:
    return max(1, int(getattr(cfg.guard, "lab_traffic_limit", 50)))
