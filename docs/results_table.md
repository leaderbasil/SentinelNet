# جدول نتائج المشروع (قبل/بعد الضوابط)
املأ هذا الجدول أثناء تكرار التجارب (الهجمات الخمس × الحالتان A ثم B).
لكل صف: هل نجح الهجوم؟ هل كشفته الأداة؟ بعد كم ثانية؟ مع لقطة + ملف PCAP.

## الحالة A — خط الأساس الضعيف
| # | الهجوم | نجح الهجوم؟ | كشفته الأداة؟ | زمن الكشف (ث) | لقطة/PCAP |
|---|---|---|---|---|---|
| 1 | Sniffing (تنصت سلبي) | | (تنبيه إرشادي HTTP/DNS) | | screenshots/01_sniff_A.png |
| 2 | ARP Spoofing → MITM | | | | screenshots/02_mitm_A.png |
| 3 | Deauth Flood | | | | screenshots/03_deauth_A.png |
| 4 | Evil Twin | | | | screenshots/04_twin_A.png |
| 5 | ضيف → منطقة الإدارة | | | | screenshots/05_guest_A.png |

## الحالة B — بعد الضوابط (WPA3+PMF، تقسيم، nftables، TLS، الأداة)
| # | الهجوم | نجح الهجوم؟ | كشفته الأداة؟ | زمن الكشف (ث) | لقطة/PCAP |
|---|---|---|---|---|---|
| 1 | Sniffing | | | | screenshots/01_sniff_B.png |
| 2 | ARP Spoofing → MITM | | | | screenshots/02_mitm_B.png |
| 3 | Deauth Flood (PMF) | | | | screenshots/03_deauth_B.png |
| 4 | Evil Twin (baseline) | | | | screenshots/04_twin_B.png |
| 5 | ضيف → منطقة الإدارة | | | | screenshots/05_guest_B.png |

## ملاحظات القياس
- زمن الكشف = فرق التوقيت بين بداية أول حزمة و أول تنبيه (سجل alerts.jsonl فيه "time").
- الإنذارات الكاذبة: شغّل مرورًا سليمًا 30 دقيقة على الأقل وعدّ التنبيهات غير المرتبطة بأي هجوم (الهدف: 0 بعد ضبط config.yaml).
- الطرق الجاهزة للتثبت من PCAP:
  python -m detector --pcap tests/pcaps/arp_scan.pcap --mode all
  python -m detector --pcap tests/pcaps/wifi_scan.pcap --mode all
