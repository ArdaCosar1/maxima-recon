#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  MAXIMA SAAS — SUNUCU KURULUM SCRIPTI
#  Oracle Cloud / DigitalOcean / Hetzner / Herhangi bir VPS
# ══════════════════════════════════════════════════════════════
#
#  Kullanim:
#    1. VPS'e SSH ile baglan: ssh ubuntu@sunucu-ip
#    2. Bu scripti kopyala: nano setup-server.sh
#    3. Calistir: chmod +x setup-server.sh && sudo ./setup-server.sh
#
# ══════════════════════════════════════════════════════════════

set -e

DOMAIN="${1:-yourdomain.com}"
EMAIL="${2:-admin@yourdomain.com}"
APP_DIR="/opt/maxima"

echo "═══════════════════════════════════════════"
echo "  MAXIMA SAAS — Sunucu Kurulumu"
echo "  Domain: $DOMAIN"
echo "═══════════════════════════════════════════"

# ── 1. Sistem guncelleme ──
echo "[1/8] Sistem guncelleniyor..."
apt-get update -y && apt-get upgrade -y

# ── 2. Gerekli paketler ──
echo "[2/8] Paketler kuruluyor..."
apt-get install -y \
    python3 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    git curl ufw

# ── 3. Firewall ──
echo "[3/8] Firewall ayarlaniyor..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# ── 4. Uygulama dizini ──
echo "[4/8] Uygulama kuruluyor..."
mkdir -p $APP_DIR
cd $APP_DIR

if [ -d ".git" ]; then
    git pull origin main
else
    echo "  Projeyi $APP_DIR dizinine kopyalayin."
    echo "  Ornek: git clone <repo-url> $APP_DIR"
    echo "  veya:  scp -r maxima_v11_final/* ubuntu@sunucu:$APP_DIR/"
fi

# ── 5. Python virtual environment ──
echo "[5/8] Python ortami hazirlaniyor..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-saas.txt

# ── 6. Environment dosyasi ──
if [ ! -f ".env" ]; then
    echo "[6/8] .env dosyasi olusturuluyor..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    cat > .env << ENVEOF
SECRET_KEY=$SECRET
DATABASE_URL=sqlite:///$APP_DIR/data/maxima_saas.db
SITE_URL=https://$DOMAIN
MAX_CONCURRENT_SCANS=5

# Stripe (https://dashboard.stripe.com'dan al)
STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_PRO=
STRIPE_PRICE_ENTERPRISE=
ENVEOF
    mkdir -p $APP_DIR/data
    echo "  .env dosyasi olusturuldu. Stripe anahtarlarini ekleyin!"
else
    echo "[6/8] .env zaten mevcut, atlaniyor."
fi

# ── 7. Systemd servisi ──
echo "[7/8] Systemd servisi olusturuluyor..."
cat > /etc/systemd/system/maxima.service << SVCEOF
[Unit]
Description=Maxima SaaS Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/python -m uvicorn saas.app:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable maxima
systemctl start maxima

# ── 8. Nginx + SSL ──
echo "[8/8] Nginx ve SSL ayarlaniyor..."
cat > /etc/nginx/sites-available/maxima << NGXEOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 600s;
    }
}
NGXEOF

ln -sf /etc/nginx/sites-available/maxima /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
mkdir -p /var/www/certbot

# SSL sertifikasi al
echo "  SSL sertifikasi aliniyor..."
certbot --nginx -d $DOMAIN -d www.$DOMAIN --email $EMAIL --agree-tos --non-interactive || {
    echo "  SSL alinamadi. Once domain'i sunucuya yonlendirin."
    echo "  Sonra tekrar calistirin: certbot --nginx -d $DOMAIN"
}

nginx -t && systemctl reload nginx

echo ""
echo "═══════════════════════════════════════════"
echo "  KURULUM TAMAMLANDI!"
echo "═══════════════════════════════════════════"
echo ""
echo "  Site: https://$DOMAIN"
echo "  API:  https://$DOMAIN/api/docs"
echo ""
echo "  Yapilmasi gerekenler:"
echo "  1. Domain DNS'ini bu sunucunun IP'sine yonlendirin"
echo "  2. .env dosyasina Stripe anahtarlarini ekleyin:"
echo "     nano $APP_DIR/.env"
echo "  3. Servisi yeniden baslatin:"
echo "     systemctl restart maxima"
echo ""
echo "  Loglar:  journalctl -u maxima -f"
echo "  Durum:   systemctl status maxima"
echo "═══════════════════════════════════════════"
