#!/usr/bin/env bash
# ================================================================
#  MAXIMA v11.0 — Installer (Linux / macOS / WSL / Git Bash)
#  Kullanım:
#    Linux/macOS: sudo bash install.sh
#    Windows:     bash install.sh   (Git Bash / WSL)
# ================================================================

set -euo pipefail

# ── Renkler ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[!]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  +--------------------------------------------+"
echo "  |        MAXIMA v11.0 FRAMEWORK INSTALLER    |"
echo "  +--------------------------------------------+"
echo -e "${NC}"

# ── Script dizini ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── İşletim sistemi tespiti ───────────────────────────────────────
OS_TYPE="$(uname -s)"
IS_WINDOWS=false

case "$OS_TYPE" in
    MINGW*|MSYS*|CYGWIN*)
        IS_WINDOWS=true
        info "Windows ortamı tespit edildi (Git Bash / MSYS2)"
        ;;
    Linux)
        # WSL kontrolü
        if grep -qi microsoft /proc/version 2>/dev/null; then
            info "WSL ortamı tespit edildi"
        else
            info "Linux ortamı tespit edildi"
        fi
        ;;
    Darwin)
        info "macOS ortamı tespit edildi"
        ;;
esac

# ── Windows kurulumu ──────────────────────────────────────────────
if $IS_WINDOWS; then
    info "Windows kurulumu başlatılıyor..."

    # Python kontrolü — Windows'ta birden fazla konum denenecek
    PYTHON=""
    ver=""

    # Bilinen Windows Python konumları
    WIN_PYTHON_PATHS=(
        "$LOCALAPPDATA/Programs/Python/Python313/python.exe"
        "$LOCALAPPDATA/Programs/Python/Python312/python.exe"
        "$LOCALAPPDATA/Programs/Python/Python311/python.exe"
        "$LOCALAPPDATA/Programs/Python/Python310/python.exe"
        "$LOCALAPPDATA/Programs/Python/Python39/python.exe"
        "$LOCALAPPDATA/Programs/Python/Python38/python.exe"
        "C:/Python313/python.exe"
        "C:/Python312/python.exe"
        "C:/Python311/python.exe"
        "C:/Python310/python.exe"
    )

    # Önce PATH'teki python'ı dene (WindowsApps alias'ı hariç)
    for candidate in python python3; do
        if command -v "$candidate" &>/dev/null; then
            cpath="$(command -v "$candidate")"
            # WindowsApps alias'ını atla (çalışmıyor)
            if [[ "$cpath" == *"WindowsApps"* ]]; then
                continue
            fi
            ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
            major=$("$candidate" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
            if [[ "$major" -ge 3 ]]; then
                PYTHON="$candidate"
                break
            fi
        fi
    done

    # PATH'te bulunamadıysa bilinen konumları dene
    if [[ -z "$PYTHON" ]]; then
        for ppath in "${WIN_PYTHON_PATHS[@]}"; do
            if [[ -f "$ppath" ]]; then
                ver=$("$ppath" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
                major=$("$ppath" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
                if [[ "$major" -ge 3 ]]; then
                    PYTHON="$ppath"
                    break
                fi
            fi
        done
    fi

    # py launcher son çare
    if [[ -z "$PYTHON" ]]; then
        if command -v py &>/dev/null; then
            PYTHON="py -3"
            ver=$(py -3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "?")
        fi
    fi

    if [[ -z "$PYTHON" ]]; then
        die "Python 3 bulunamadı. https://python.org adresinden kurun ve PATH'e ekleyin."
    fi

    info "Python: $PYTHON (sürüm: $ver)"

    # pip ile bağımlılıklar
    REQ_FILE="${SCRIPT_DIR}/requirements.txt"
    if [[ -f "$REQ_FILE" ]]; then
        info "Bağımlılıklar kuruluyor..."
        if $PYTHON -m pip install -r "$REQ_FILE" -q 2>/dev/null; then
            success "Bağımlılıklar kuruldu"
        else
            warn "Bazı bağımlılıklar yüklenemedi — devam ediliyor."
        fi
    fi

    # Windows batch dosyası oluştur
    BATCH_DIR="$SCRIPT_DIR"
    cat > "${BATCH_DIR}/maxima.bat" << BEOF
@echo off
cd /d "%~dp0"
$PYTHON maxima.py %*
BEOF
    success "maxima.bat oluşturuldu"

    # PowerShell profili bilgisi
    WIN_PATH=$(cd "$SCRIPT_DIR" && pwd -W 2>/dev/null || echo "$SCRIPT_DIR")

    echo ""
    echo -e "${GREEN}${BOLD}  +--------------------------------------------+"
    echo -e "  |  Windows kurulumu tamamlandı!              |"
    echo -e "  +--------------------------------------------+${NC}"
    echo ""
    echo -e "${BOLD}Kullanım:${NC}"
    echo -e "  ${CYAN}maxima.bat <hedef>${NC}                  # CMD'den"
    echo -e "  ${CYAN}$PYTHON maxima.py <hedef>${NC}           # Doğrudan"
    echo -e "  ${CYAN}$PYTHON maxima.py <hedef> --all --turbo${NC}  # Turbo tarama"
    echo -e "  ${CYAN}$PYTHON maxima.py --panel${NC}           # Modül paneli"
    echo ""
    echo -e "${BOLD}PATH'e eklemek için (opsiyonel):${NC}"
    echo -e "  ${YELLOW}PowerShell:${NC} \$env:PATH += \";${WIN_PATH}\""
    echo -e "  ${YELLOW}CMD:${NC}        set PATH=%PATH%;${WIN_PATH}"
    echo -e "  ${YELLOW}Kalıcı:${NC}     Sistem Ayarları → Ortam Değişkenleri → Path'e ekle"
    echo ""
    echo -e "${GREEN}Raporlar: ${WIN_PATH}\\maxima_reports${NC}"
    exit 0
fi

# ── Linux / macOS kurulumu ────────────────────────────────────────

# Paket yöneticisi tespiti
detect_pkg_manager() {
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            PKG_MANAGER="brew"
        else
            die "macOS tespit edildi fakat Homebrew bulunamadı. Kurulum: https://brew.sh"
        fi
    elif command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
    else
        die "Desteklenen paket yöneticisi bulunamadı (apt-get/dnf/yum/pacman/zypper/brew)"
    fi
    info "Paket yöneticisi: ${PKG_MANAGER}"
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt-get) apt-get install -y "$@" ;;
        dnf)     dnf install -y "$@" ;;
        yum)     yum install -y "$@" ;;
        pacman)  pacman -S --noconfirm "$@" ;;
        zypper)  zypper install -y "$@" ;;
        brew)    brew install "$@" ;;
    esac
}

pkg_update() {
    case "$PKG_MANAGER" in
        apt-get) apt-get update -qq ;;
        dnf)     dnf check-update -q || true ;;
        yum)     yum check-update -q || true ;;
        pacman)  pacman -Sy --noconfirm ;;
        zypper)  zypper refresh -q ;;
        brew)    brew update -q ;;
    esac
}

get_python_pkgs() {
    case "$PKG_MANAGER" in
        apt-get)       echo "python3 python3-pip" ;;
        dnf|yum)       echo "python3 python3-pip" ;;
        pacman)        echo "python python-pip" ;;
        zypper)        echo "python3 python3-pip" ;;
        brew)          echo "python3" ;;
    esac
}

get_pip_pkg() {
    case "$PKG_MANAGER" in
        apt-get)       echo "python3-pip" ;;
        dnf|yum)       echo "python3-pip" ;;
        pacman)        echo "python-pip" ;;
        zypper)        echo "python3-pip" ;;
        brew)          echo "python3" ;;
    esac
}

get_tk_pkg() {
    case "$PKG_MANAGER" in
        apt-get)       echo "python3-tk" ;;
        dnf|yum)       echo "python3-tkinter" ;;
        pacman)        echo "tk" ;;
        zypper)        echo "python3-tk" ;;
        brew)          echo "python-tk" ;;
    esac
}

detect_pkg_manager

# Sabitler
INSTALL_DIR="/opt/maxima"
BIN_CLI="/usr/local/bin/maxima"
BIN_GUI="/usr/local/bin/maxima-gui"
REPORTS_DIR="${INSTALL_DIR}/maxima_reports"

# Root kontrolü
if [[ "$OS_TYPE" != "Darwin" && "$EUID" -ne 0 ]]; then
    die "Root yetkisi gerekli. Kullanım: sudo bash install.sh"
fi

# python3 kontrolü
if ! command -v python3 &>/dev/null; then
    info "python3 bulunamadı, yükleniyor..."
    pkg_update && pkg_install $(get_python_pkgs) \
        || die "python3 yüklenemedi. Elle yükleyin ve tekrar deneyin."
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python sürümü: ${PYTHON_VERSION}"

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' \
    || die "Python 3.8+ gerekli (bulunan: ${PYTHON_VERSION})"

# pip3 kontrolü
if ! command -v pip3 &>/dev/null; then
    info "pip3 bulunamadı, yükleniyor..."
    pkg_install $(get_pip_pkg) || die "pip3 yüklenemedi."
fi

# requirements.txt
REQ_FILE="${SCRIPT_DIR}/requirements.txt"
[[ -f "$REQ_FILE" ]] || die "requirements.txt bulunamadı: ${REQ_FILE}"

# Python bağımlılıklar
info "Python bağımlılıklar kuruluyor..."
if pip3 install -r "$REQ_FILE" --break-system-packages -q 2>/dev/null; then
    success "Bağımlılıklar kuruldu (--break-system-packages)"
elif pip3 install -r "$REQ_FILE" -q 2>/dev/null; then
    success "Bağımlılıklar kuruldu"
else
    warn "Bazı bağımlılıklar yüklenemedi — devam ediliyor."
fi

# tkinter kontrolü (GUI için)
info "tkinter kontrol ediliyor..."
if ! python3 -c "import tkinter" 2>/dev/null; then
    warn "tkinter bulunamadı, yükleniyor..."
    pkg_install $(get_tk_pkg) 2>/dev/null \
        && success "tkinter kuruldu" \
        || warn "tkinter yüklenemedi — 'maxima-gui' komutu çalışmayabilir."
else
    success "tkinter mevcut"
fi

# Dosyaları kopyala
info "Dosyalar kopyalanıyor: ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
rm -rf "${INSTALL_DIR:?}"/*
cp -r "${SCRIPT_DIR}/." "$INSTALL_DIR/"
chmod +x "${INSTALL_DIR}/maxima.py"
mkdir -p "$REPORTS_DIR"
success "Dosyalar kopyalandı"

# CLI sarıcı: /usr/local/bin/maxima
info "CLI komutu oluşturuluyor: maxima"
cat > "$BIN_CLI" << 'EOF'
#!/usr/bin/env bash
cd /opt/maxima
exec python3 maxima.py "$@"
EOF
chmod +x "$BIN_CLI"
success "maxima komutu hazır"

# GUI sarıcı: /usr/local/bin/maxima-gui
info "GUI komutu oluşturuluyor: maxima-gui"
cat > "$BIN_GUI" << 'EOF'
#!/usr/bin/env bash
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "[!] tkinter bulunamadı. Kurmak için: sudo bash /opt/maxima/install.sh"
    exit 1
fi
exec python3 /opt/maxima/maxima_gui.py "$@"
EOF
chmod +x "$BIN_GUI"
success "maxima-gui komutu hazır"

# Kurulum özeti
echo ""
echo -e "${GREEN}${BOLD}  +--------------------------------------------+"
echo -e "  |  Kurulum başarıyla tamamlandı!             |"
echo -e "  +--------------------------------------------+${NC}"
echo ""
echo -e "${BOLD}Kullanım:${NC}"
echo -e "  ${CYAN}maxima <hedef>${NC}                      # İnteraktif menü"
echo -e "  ${CYAN}maxima <hedef> --all${NC}                # Tüm modüller"
echo -e "  ${CYAN}maxima <hedef> --all --turbo${NC}        # TURBO: ~3-5x hızlı"
echo -e "  ${CYAN}maxima <hedef> --module 14${NC}          # Tek modül"
echo -e "  ${CYAN}maxima <hedef> --scan vuln${NC}          # Güvenlik açığı paketi"
echo -e "  ${CYAN}maxima <hedef> --scan web --turbo${NC}   # Web paketi turbo"
echo -e "  ${CYAN}maxima <hedef> --output json${NC}        # JSON çıktı"
echo -e "  ${CYAN}maxima --panel${NC}                      # Modül paneli"
echo -e "  ${CYAN}maxima-gui${NC}                          # Grafik arayüz"
echo ""
echo -e "${BOLD}Örnekler:${NC}"
echo -e "  ${CYAN}maxima https://testsite.com${NC}"
echo -e "  ${CYAN}maxima 192.168.1.1 --all --turbo${NC}"
echo -e "  ${CYAN}maxima target.com --module 2${NC}        # Port Scanner"
echo ""
echo -e "${GREEN}Raporlar: ${REPORTS_DIR}${NC}"
