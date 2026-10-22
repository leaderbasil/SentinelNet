# NetGuard-IDS — كاشف الهجمات الشبكية باستخدام Scapy

أداة **دفاعية**: تكشف هجمات الشبكة وتبنّه بصوتها وتحفظ الأدلة، ولا تنفّذ أي هجوم.

| الهجوم | كيف تنبّهك الأداة |
|---|---|
| MITM عبر ARP Spoofing | حديث تعيين IP↔MAC (خصوصًا البوابة) / ردود بلا طلب |
| Deauth (فصل إجباري) | عدد إطارات فصل مرتفع خلال نافذة زمنية قصيرة |
| Evil Twin | BSSID غير معرف يعلن SSID مشروعًا (بخط أساس) أو نفس SSID من BSSID مختلف |
| مخاطر Sniffing | مرور HTTP غير مشفر قابل للاعتراض (إرشاد) |
| محاولة وصول | تنبيه HTTP غير مشفر أو جدار الناري عند الحظر (منطق تمارين المعلم) |

---

## 1) التثبيت

```powershell
cd "Desktop\scopy scan"
python -m pip install -r requirements.txt   # scapy, colorama, pyyaml, pytest
python main.py selftest                     # يجب: PASS لكل الكواشف الستة
```

## 2) التشغيل

### أ) محاكاة آمنة (العرض — لا حزم على الشبكة)
```powershell
python main.py simulate
```

### ب) قراءة ملفات PCAP (بدون صلاحيات ما يليها التقاط)
```powershell
python tests/gen_test_pcaps.py                       # توليد مختبرات اصطناعية
python -m detector --pcap tests/pcaps/arp_scan.pcap  --mode all
python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all
```

### ج) الالتقاط الحقيقي (يحتاج Npcap على Windows + صلاحيات مسؤول)
```powershell
python main.py list-ifaces
python -m detector --iface "Wi-Fi" --mode arp         # MITM عبر ARP
python -m detector --iface <iface> --mode wifi        # يحتاج وضع المراقبة (Linux)
python -m detector --iface "Ethernet" --mode all --log-dir ./logs
```

## 3) البلاغات والأدلة
- `logs/alerts_*.jsonl` — كل تنبيه (زمن، النوع، الشدة، التفاصيل).
- `logs/evidence_*.pcap` — الحزم المشبوهة (فتحها في Wireshark).
- `logs/manifest_*.json` — بصمة SHA-256 لكل ملف أدلة، وتتحقق منها:
```powershell
python tools/verify.py logs
```

## 4) الإعدادات (config.yaml)
عتبات كل كاشف (فيض ARP، نافذة Deauth، طاقة الشظر سياز)... لا قيم ثابتة داخل الكود. مفاتيح مهمة:
- `arp.whitelist`: روابط شرعية تُثبّت من الدخول (مثال: البوابة).
- `evil_twin.allowed_aps_file`: خط أساس نقاط الوصول الشرعية `lab/allowed_aps.yaml`.
- `guard`: ضوابط السلامة للمختبر (قائمة واجهات، حد الحزم 50، فحص الانترنت).

## 5) الاختبارات (pytest — بلا هجمات حية)
```powershell
python -m pytest tests/test_arp.py tests/test_deauth.py tests/test_eviltwin.py -q
python -m pytest -q        # أو كل شيء
```
لكل كاشف: حالة تنبيه + حالة سليم ينبغي الصمت (12 اختبارًا الآن، كلها ناجحة).

## 6) مختبر الحرم الجامعي (في VM — Linux)
راجع `lab/README.md`: الحالتان A/B (`setup_baseline.sh` / `setup_hardened.sh`)،
إعدادات hostapd (WPA3-SAE + PMF)، قواعد nftables، ومحاكاها اللاسلكي
(mac80211_hwsim) — مع خطة PCAP البديلة (الأسهل لتثبيت اكتشفها في تقارير).

## 7) الإطار القانوني
أداة مراقب فقط. اختبار على مختبرك أو بإذن مكتوب. سكربت النيافة الفعلية
(`tests/lab_spoof_sim.py`) مقفل بضوابط السلامة لاحظ — ولا يعمل على شبكة فارغ
منه بإنترنت أو واجهة غير معلحة في `guard.allowed_interfaces`.

## 8) الإفصاح عن استخدام الذكاء الاصطناعي
استُعين بمساعد ذكاء اصطناعي في كتابة الكود والوثائق المستخدمة في هذا المستودع
(كشفت به وفقًا لإلزام قسم 8 من الوثيقة الرسمية). الكون: الدفاعي والاختبارات والضوابط
هي ما نُنفذ، وقد كذلك تحcrafted من المشرف عبر اختبارات إعادة الضب مع اللجنة.

## 9) هيكل المستودع
```
main.py                        نقطة التشغيل (sniff/simulate/selftest/list-ifaces)
detector/__main__.py           python -m detector --iface/--pcap
config.yaml                    العتبات والقوائم (بدون قيم داخل الكود)
ids_tool/
  sniffer.py                   المحرك (التقاط حي أو تشغيل PCAP)
  alerts.py                    التنبيهات (شاشة + JSONL)
  evidence.py                  الأدلة + SHA-256
  guard.py                     ضوابط السلامة (القسم 8)
  simulator.py                 محاكاة استعرضية للعرض
  detectors/arp_spoofing.py    MITM عبر ARP (تغيير تعيين، فيض، ردود بلا طلب)
  detectors/deauth.py          الفصل الإجباري (لكل زوج + رمز السبب)
  detectors/evil_twin.py       نقطة متزداز (خط أساس + RSN + قناة/تشفير)
  detectors/...                 ...
tests/                         pytest (12) + pert pcap websites
tools/verify.py                تحقق سلامة الأدلة SHA-256
lab/                           قوالب الحالتين A/B + hostapd + nftables + خط الأساس
docs/                          التقرير: نظري + جدول النتائج + خطة
```
