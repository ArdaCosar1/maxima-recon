#!/bin/bash
# Maxima SaaS — Guncelleme Scripti
# Kullanim: sudo ./deploy/update.sh

set -e
APP_DIR="/opt/maxima"
cd $APP_DIR

echo "[*] Kod cekiliyor..."
git pull origin main

echo "[*] Bagimliliklar guncelleniyor..."
source venv/bin/activate
pip install -r requirements-saas.txt --quiet

echo "[*] Servis yeniden baslatiliyor..."
systemctl restart maxima

echo "[*] Durum kontrol..."
sleep 2
systemctl status maxima --no-pager | head -5

echo "[+] Guncelleme tamamlandi!"
