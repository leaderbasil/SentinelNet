#!/usr/bin/env bash
# الحالة B — بعد تطبيق الضوابط الأمنية (يعمل على جهاز الموجّه)
set -euo pipefail
echo "[B] applying hardened nftables policy"
sudo nft -f nftables/hardened.nft

echo "[B] AP: WPA3-SAE with mandatory PMF  (hostapd/hostapd/ap_wpa3.conf)"
# sudo hostapd hostapd/ap_wpa3.conf &

echo "[B] Mgmt server TLS: use a self-signed certificate (openssl req ...)
      or nginx with ssl_certificate; port 443 only."
# sudo openssl req -x509 -nodes -newkey rsa:2048 \
#   -keyout mgmt.key -out mgmt.crt -days 30 -subj "/CN=mgmt.campus.lab" 2>/dev/null

echo "[B] detector: start on the monitor machine"
# python -m detector --iface eth0 --mode arp
echo "[B] done. Repeat the SAME 5 attack tests and compare results."
