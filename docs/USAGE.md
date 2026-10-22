# دليل الاستخدام الكامل — NetGuard-IDS
تم التحقق منه على الجهاز: SELFTEST 6/6 ✅ | pytest 12/12 ✅ | verify ALL VERIFIED ✅

يعرض الأداة وضعين جوهريين: **التقاط حي من واجهة** أو **قراءة ملف PCAP**،
بثلاثة أنماط: `arp` (سلكي) / `wifi` (802.11) / `all` (شامل).

---

## 0) التثبيت والتحقق (مرة واحدة)
```powershell
cd "Desktop\scopy scan"
python -m pip install -r requirements.txt    # scapy, colorama, pyyaml, pytest
python main.py selftest                      # يجب أن ترى 6 PASS
```
- Windows + التقاط حي = ثبّت Npcap من https://npcap.com وافتح الطرفية **بصلاحيات Administrator**.
- المحاكاة وقراءة PCAP لا تحتاج أي صلاحيات ولا Npcap.

---

## السيناريو 1 — العرض أمام اللجنة (محاكاة آمنة 100%)
```powershell
python main.py simulate
```
- تمر بعدة مراحل يرويها البرنامج نفسه: مرور طبيعي، انتحال البوابة (MITM)،
  ردود غير مطلوبة، فيض ARP، Evil Twin، Deauth، HTTP غير مشفر.
- كل الحزم تُبنى في الذاكرة فقط… ولا شيء يخرج للشبكة إطلاقًا.
- مدة العرض ~20 ثانية. مناسب كأول عرض أمام الجمهور.

---

## السيناريو 2 — اختبار PCAP (بدون وضع مراقبة — البديل اللاسلكي)
```powershell
python tests/gen_test_pcaps.py                                  # يولّد الملفين
python -m detector --pcap tests/pcaps/arp_scan.pcap  --mode all # سلوك MITM
python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all # Deauth + Evil Twin
```
- نتائج متوقعة: `arp_scan` يطلق 5 تنبيهات (MITM بوابة، ARP_SPOOF،
  UNSOLICITED_ARP، MAC_FLOOD، PLAINTEXT_TRAFFIC)، و`wifi_scan` يطلق
  EVIL_TWIN + DEAUTH_FLOOD.
- خيارات مفيدة: `--quiet` (تنبيهات فقط)، `--log-dir ./mylogs`، `--config config.yaml`.
- مناسب لإعادة العرض مرارًا بنفس الشروط، وبالمقارنة بين الحالتين A/B.

---

## السيناريو 3 — مراقبة حية لمرور ARP على جهازك (كشف MITM)
```powershell
python main.py list-ifaces                                # انسخ اسم الواجهة
python -m detector --iface "Wi-Fi" --mode arp             # التقاط حتى Ctrl+C
python -m detector --iface "Wi-Fi" --mode arp --timeout 120 --quiet
```
- تظهر سطور `[ARP] new device on network: IP -> MAC` لكل جهاز جديد.
- لو أحد أطلق ردود انتحال → تنبيه فوري + حزم موثقة كأدلة.
- على شبكة منزلية سليمة غالبًا لن تتنبه إلا الإرشادات… هذا طبيعي.
- للحصول على تنبيه حي فعلًا (اختبار تحدٍ): استخدم السيناريو 5.

---

## السيناريو 4 — مراقبة واي فاي حية (Linux / VM فقط — وضع المراقبة)
```bash
sudo airmon-ng start wlan0            # أو iw dev wlan0 set monitor control none
python -m detector --iface wlan0mon --mode wifi
```
- يرصد Beacons، إطارات Deauth، تغيّر تشفير/قناة AP.
- ترتيب المختبر (mac80211_hwsim): التقاط على `hwsim0` يرى كل الراديوهات.

---

## السيناريو 5 — المختبر الافتراضي الكامل (إثبات هجوم حقيقي داخل شبكة معزولة)
أ) جهّز مختبرًا حسب `lab/README.md` (VirtualBox شبكات داخلية فقط، بلا إنترنت).
ب) على جهاز المراقبة (Linux أو Windows مع Npcap):
```powershell
python -m detector --iface "Ethernet" --mode arp
```
ج) على جهاز "المهاجم":
```powershell
python tests\lab_spoof_sim.py --iface "Ethernet" --gateway-ip 10.20.0.1 `
    --victim-ip 10.20.0.50 --confirm "I OWN THIS LAB"
```
- ضوابط إجبارية: الواجهة يجب أن تكون في `config.yaml → guard.allowed_interfaces`،
  والجهاز **بلا اتصال إنترنت**، والحد الافتراضي 50 حزمة.
- خيار الإصلاح بعد الاختبار: `--cleanup <MAC البوابة الحقيقي>`.

---

## السيناريو 6 — Evil Twin مع خط أساس النقاط الشرعية
```yaml
# lab/allowed_aps.yaml
- ssid: Campus-Students
  bssid: "66:77:88:99:aa:a1"
  channel: 6
  security: WPA2/WPA3 (RSN)
```
```powershell
python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode wifi
```
- BSSID مسجل → سطر `[WLAN] legitimate AP seen` هادئ.
- BSSID جديد بنفس SSID → تنبيه `EVIL_TWIN` عالي.
- شبكة غير مسجلة إطلاقًا → `UNKNOWN_AP` إرشادي (تقيمها وتضيفها يدويًا).
- تغيّر تشفير/قناة AP معروف → تنبيهات `BEACON_PRIVACY_CHANGE` / `AP_CHANNEL_CHANGE`.

---

## السيناريو 7 — مقارنة الحالتين A/B (منهجية المشروع)
1. داخل VM: `bash lab/setup_baseline.sh` → نفّذ التجارب الخمس → سجّل في ملف
   `docs/results_table.md` (قسم A).
2. `bash lab/setup_hardened.sh` (WPA3-SAE + PMF، nftables، TLS) → كرر **نفس**
   التجارب بنفس الترتيب → سجل في قسم B.
3. زمن الكشف = فرق أول حزمة وأول تنبيه (الوقت في `alerts.jsonl`).

---

## السيناريو 8 — ضبط السلوك عبر config.yaml
```yaml
arp:
  mac_flood_threshold: 10
  unsolicited_reply_threshold: 6
  whitelist:
    - {ip: 192.168.1.1,     mac: aa:bb:cc:dd:ee:ff}
    - {ip: 192.168.1.50,    mac: aa:bb:cc:00:00:50}
deauth:
  alert_threshold: 10
  window_seconds: 10.0
evil_twin:
  allowed_aps_file: lab/allowed_aps.yaml
  ignored_ssids: []           # شبكات Mesh/Repeaters معروفة
alerts:
  cooldown_seconds: 15.0
guard:
  allowed_interfaces: ["Ethernet"]   # واجهات المختبر المسموح بها للمولدات
  lab_traffic_limit: 50
  require_isolated_link: true
```
العثور على MAC البوابة: `arp -a` ثم أدخله في whitelist لتثبيته.

---

## جدول التنبيهات ومعانيها
| النوع | الشدة | معناه | خطوة الحماية |
|---|---|---|---|
| ARP_SPOOF | عالية | MAC مختلف لنفس IP — أساس هجوم MITM | حجب MAC، Static ARP للبوابة، DAI |
| MAC_FLOOD | متوسطة | MAC يدّعي عدد IPs كبير | زكّ جدول، راجع الجهاز والسويتش |
| UNSOLICITED_ARP | متوسطة | ردود ARP بلا طلب بمعدل مرتفع | مثل ARP_SPOOF |
| DEAUTH_FLOOD | عالية | إطارات فصل كثيرة خلال نافذة | WPA3+PMF، راقب إعادة الاتصال |
| EVIL_TWIN | عالية | SSID من BSSID غير معروف/مكرر | لا تتصل بها، راجع قناة المنطقة |
| BEACON_PRIVACY_CHANGE / AP_CHANNEL_CHANGE | متوسطة | تغيّر سلوك AP معروف | راجع من قام بتغييره |
| UNKNOWN_AP | إرشادية | نقطة غير بخط الأساس | إضافة يدوية إن كانت شرعية |
| PLAINTEXT_TRAFFIC | إرشادية | HTTP غير مشفر قابل للاعتراض | HTTPS/VPN للبيانات الحساسة |

---

## ملفات الأدلة والتفريغ
- `logs/alerts_YYYYmmdd_HHMMSS.jsonl` — كل تنبيه مع زمنه وتفاصيله.
- `logs/evidence_*.pcap` + `evidence_*.json` — الحزم المشبوهة (Wireshark).
- `logs/manifest_*.json` — بصمة SHA-256؛ التحقق: `python tools/verify.py logs`
  → المخرج المتوقع `RESULT: ALL VERIFIED`.
- التدقيق اليدوي في Wireshark: افتح ملف `evidence_*.pcap` ثم فلتر `arp` أو `wlan`.

---

## اختبارات المطور (pytest)
```powershell
python -m pytest -q                                  # كل الاختبارات (12)
python -m pytest tests/test_arp.py -q                # وحدة واحدة
```

## استكشاف الأخطاء
| المشكلة | الحل |
|---|---|
| `winpcap is not installed` | نصب Npcap + افتح الطرفي كمسؤول |
| الوضع wifi يلتقط صفرًا على Windows | خذ PCAP بدلاً منه (السيناريو 2) |
| مولد المختبر رفض العمل | سجّل الواجهة في guard.allowed_interfaces + أوقف الإنترنت |
| إغراق بتنبيهات وتكرار | زيادة `cooldown_seconds` أو ثبّت whitelist |
| تعذر استيراد ids_tool في pytest | شغّل من جذر المشروع |
