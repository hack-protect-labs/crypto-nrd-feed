#!/bin/bash
PATH=/usr/local/sbin:$PATH

# Barvne funkcije za izpis v terminalu
function echo.Red() {
  echo -e "\033[31m$*\033[m"
}

function echo.Green() {
  echo -e "\033[32m$*\033[m"
}

function echo.Cyan() {
  echo -e "\033[36m$*\033[m"
}

function error() {
    echo.Red >&2 "$@"
    exit 1
}

# Preverjanje obveznih ukazov v sistemu
for cmd in mkdir wc base64 curl cat zcat mktemp date tr realpath dirname sort awk grep; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        error "command: $cmd not found!"
    fi
done
set -e

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
DAY_RANGE="${DAY_RANGE:-1}"
DAILY_DIR="${DAILY_DIR:-daily}"
TEMP_FILE="$(mktemp -p "$DIR" --suffix=nrd)"

# Poverilnice se preberejo iz okoljskih spremenljivk (varno za GitHub Actions Secrets)
PAID_WHOISDS_USERNAME="${WHOISDS_USER:-}"
PAID_WHOISDS_PASSWORD="${WHOISDS_PASS:-}"

BASE_URL_FREE="https://whoisds.com/whois-database/newly-registered-domains"
BASE_URL_PAID="https://whoisds.com/your-download/direct-download_file/${PAID_WHOISDS_USERNAME}/${PAID_WHOISDS_PASSWORD}"

cd "$DIR"
echo.Green "HackProtect Labs | NRD Downloader & Crypto Filter zagnan..."

function download() {
    local i="$DAY_RANGE"
    local TYPE="${1:-free}"
    local DOWNLOAD_DIR="${DAILY_DIR}/${TYPE}"
    mkdir -p "$DOWNLOAD_DIR"

    echo.Cyan "Prenašam $TYPE NRD listo (zadnjih $DAY_RANGE dni)..."

    while [ "$i" -gt "0" ]; do
        DATE="$(date -u --date "$i days ago" '+%Y-%m-%d')"
        FILE="${DOWNLOAD_DIR}/${DATE}"
        if [ -s "$FILE" ] && [ "$(grep -vc '^$' "$FILE")" -ge "1" ] ; then
            echo.Cyan "$FILE že obstaja, preskakujem prenos..."
        else
            printf "%s" "Prenašam in dekompresiram $DATE podatke... "
            if [ "paid" = "$TYPE" ]; then
                URL="${BASE_URL_PAID}/${DATE}.zip/ddu"
            else
                FREE_URL_INFIX="$(echo "${DATE}.zip" | base64)"
                URL="${BASE_URL_FREE}/${FREE_URL_INFIX:0:-1}/nrd"
            fi
            curl -sSLo- "$URL" | zcat | tr -d '\015' >> "$FILE"
            echo "" >> "$FILE"
        fi
        cat "$FILE" >> "$TEMP_FILE"
        i="$((i - 1))"
    done
}

# 1. Prenos prosto dostopnih (free) podatkov
download free

# 2. Prenos plačljivih podatkov, če so nastavljeni podatki za WhoisDS račun
if [ -n "$PAID_WHOISDS_USERNAME" ] && [ -n "$PAID_WHOISDS_PASSWORD" ]; then
    echo.Green "Zaznan WhoisDS plačljiv račun. Prenašam premium paket..."
    download paid
fi

# 3. KRIPTO FILTRIRANJE IN TYPOSQUATTING DETEKCIJA
echo.Cyan "Izvajam napredno kripto heuristično filtriranje (Keywords & Typosquatting)..."

# Razširjen regex za Web3/Crypto ključne besede, vključno z novimi vnosi (xpr, proton, meta) in typosquatting stemi
CRYPTO_REGEX="(crypto|wallet|dex|swap|stake|airdrop|claim|nft|mint|binance|binanc|metamask|metamsk|phantom|uniswap|uniswop|opensea|solana|ethereum|polygon|ledger|xpr|proton|meta|coin|base|kraken|cryp)"

mkdir -p feed
OUTPUT_FEED="feed/domains.txt"

# Obdelava:
# - Odstranimo komentarje in prazne vrstice
# - Filtriramo skozi kripto ključne besede (ne občutljivo na velikost črk)
# - Izločimo legitimne domene (whitelist), da preprečimo False Positives
# - Uredimo po TLD-ju za lepšo strukturo
grep -vE '^(#|$)' "$TEMP_FILE" \
    | grep -iE "$CRYPTO_REGEX" \
    | grep -viE "(binance\.com|metamask\.io|uniswap\.org|ethereum\.org|polygon\.technology|proton\.me|meta\.com)" \
    | awk -F. '{print $NF, $0}' \
    | sort -u \
    | cut -d' ' -f2- > sorted_filtered.tmp

# Izračunamo končno število filtriranih domen
TOTAL_DOMAINS=$(grep -vcE '^(#|$)' sorted_filtered.tmp)
UTC_NOW="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# 4. Zapis končnega formata z glavo (Header) v feed/domains.txt
cat << EOF > "$OUTPUT_FEED"
# =====================================================================
# Feed Name: Crypto NRD Threat Feed
# Maintainer: HackProtect Labs (@HackProtectLabs)
# Classification: TLP:CLEAR (Public sharing permitted)
# Last Updated: ${UTC_NOW}
# Total Active Domains: ${TOTAL_DOMAINS}
# Repository: https://github.com/HackProtect-Labs/crypto-nrd-feed
# Description: Automated CTI feed tracking NRDs targeting Web3/Crypto & Typosquatting
# =====================================================================
EOF

cat sorted_filtered.tmp >> "$OUTPUT_FEED"
rm -f "$TEMP_FILE" sorted_filtered.tmp

echo.Green "Uspešno! Filtriran feed s typosquatting detekcijo shranjen v $OUTPUT_FEED ($TOTAL_DOMAINS domen najdenih)."
