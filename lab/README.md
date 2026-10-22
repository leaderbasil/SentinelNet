# مختبر المشروع (يعمل داخل Linux VM — Ubuntu/Kali)
هذا المجلد يحتوي قوالب حكم الحالتين A وB وإعدادات نقطة الوصول والجدار الناري:

| الملف | الغرض |
|---|---|
| setup_baseline.sh | الحالة A — خط الأساس الضعيف (شبكة مسطحة، بلا PMF) |
| setup_hardened.sh | الحالة B — الضوابط (WPA3-SAE + PMF + تقسيم + nftables + TLS) |
| hostapd/ap_open.conf | AP مفتوح (حالة A / شبكة الضيوف) |
| hostapd/ap_wpa3.conf | AP مشفر WPA3-SAE مع PMF إجبارية (حالة B) |
| nftables/hardened.nft | قواعد رفض افتراضي مع السماح اللازم فقط |
| allowed_aps.yaml | خط أساس النقاط الشرعية (تُقرأ من config.yaml للأداة) |

## مخطط الشبكة الداخلية (VirtualBox Internal Networks)
| واجهة جهاز الموجّه | منطقه | شبكة (نموذج) |
|---|---|---|
| eth0 | الطلبة | 10.20.0.0/24 |
| eth1 | الضيوف | 10.30.0.0/24 |
| eth2 | الإدارة | 10.10.0.0/24 |

الأجهزة: موجّه/جدار ناري، طالب (Victim)، مهاجم اختبار (Attacker)،
جهاز مراقبة يعمل عليه `python -m detector --arp ...`، خادم إدارة TLS.

## الجزء اللاسلكي (mac80211_hwsim)
داخل جهاز واحد:
```
sudo modprobe mac80211_hwsim radios=4
ip netns add ap_ns ; ip netns add client_ns ; ip netns add attack_ns
# انقل كل راديو (wlan*) إلى مساحته باستخدام iw phy#N set netns
hostapd hostapd/ap_wpa3.conf          # AP شرعي
# المراقبة: التقاط الإطارات على الواجهة hwsim0 (ترى كل الراديوهات)
python -m detector --iface hwsim0 --mode wireless
```
**الخطة البديلة (الأفضل ليثبات الدرجات):** استخدم `tests/gen_test_pcaps.py`
ثم شغل الأداة على الملفات — دون الحاجة لأي راديو:
```
python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode wireless
```
