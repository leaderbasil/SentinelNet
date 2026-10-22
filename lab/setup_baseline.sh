#!/usr/bin/env bash
# الحالة A — خط الأساس الضعيف (خطوط لينة تستبدل لاحقًا بحالة B)
# تشغّل على جهاز الموجّه داخل المختبر المعزول فقط.
set -euo pipefail
echo "[A] resetting firewall: everything allowed (baseline state)"
sudo nft flush ruleset
sudo nft -f - <<'NFT'
table inet filter {
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
NFT
echo "[A] AP: open authentication, no PMF  (hostapd/hostapd/ap_open.conf)"
echo "[A] Mgmt server: plain HTTP (no TLS) - for demonstration only"
echo "[A] done. Now run: the 5 attack tests and record results."
