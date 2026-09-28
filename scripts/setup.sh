#!/usr/bin/env bash
# CodeAlpha NIDS - setup & run helper (Debian/Ubuntu/Kali)
# Installs Suricata, drops in the custom rules, and starts monitoring.
set -e

IFACE="${1:-eth0}"            # pass your interface: ./setup.sh wlan0
RULES_SRC="$(cd "$(dirname "$0")/.." && pwd)/rules/local.rules"
EVE="/var/log/suricata/eve.json"

echo "[*] Installing Suricata (needs sudo)..."
sudo apt-get update -qq
sudo apt-get install -y suricata

echo "[*] Installing custom CodeAlpha rules..."
sudo cp "$RULES_SRC" /etc/suricata/rules/local.rules
# make sure local.rules is enabled and HOME_NET is sane
sudo grep -q "local.rules" /etc/suricata/suricata.yaml || \
  echo '  - local.rules' | sudo tee -a /etc/suricata/suricata.yaml

echo "[*] Validating configuration..."
sudo suricata -T -c /etc/suricata/suricata.yaml -v

echo "[*] Starting Suricata on interface: $IFACE"
echo "    (Ctrl+C to stop. Alerts will stream to $EVE)"
sudo suricata -c /etc/suricata/suricata.yaml -i "$IFACE" &
SURI_PID=$!
sleep 3

echo "[*] Launching alert monitor..."
python3 "$(dirname "$0")/../response/monitor.py" --eve "$EVE"

kill $SURI_PID 2>/dev/null || true
