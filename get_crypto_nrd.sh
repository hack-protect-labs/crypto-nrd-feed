#!/usr/bin/env bash
# ============================================================================
# HackProtect Labs - Crypto NRD Threat Feed (GitHub Actions Production Edition)
#
# Purpose:
#   1. Securely retrieve newly registered domain (NRD) data from WhoisDS.
#   2. Safely decompress zip/gzip archives without traversal risks (No Zip-Slip).
#   3. Portable RFC 1035/1123 domain validation (100% mawk/gawk/nawk compatible).
#   4. High-efficacy detection of crypto/Web3 phishing, typosquatting & leetspeak.
#   5. Strictly append-only historical accumulation with SHRINK GUARD protection.
#   6. Atomically update CTI feed on the same filesystem with verified integrity.
# ============================================================================

set -Eeuo pipefail
umask 077

# Force deterministic byte-order and fast ASCII collation
export LC_ALL=C
export LC_COLLATE=C

IFS=$'\n\t'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [[ -d "/opt/homebrew/bin" ]]; then
    PATH="/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
fi

# ============================================================================
# Configuration & Defaults
# ============================================================================
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DAY_RANGE="${DAY_RANGE:-1}"
DAILY_DIR="${DAILY_DIR:-${SCRIPT_DIR}/daily}"
FEED_DIR="${FEED_DIR:-${SCRIPT_DIR}/feed}"
OUTPUT_FEED="${OUTPUT_FEED:-${FEED_DIR}/domains.txt}"
LOCK_FILE="${LOCK_FILE:-${SCRIPT_DIR}/.nrd-feed.lock}"
WHITELIST_FILE="${WHITELIST_FILE:-${SCRIPT_DIR}/whitelist.txt}"
STRICT_DOWNLOAD="${STRICT_DOWNLOAD:-false}"

# Shrink Guard: Dovoljen odstotek padca baze (privzeto 0% = strogo append-only)
MAX_ALLOWED_SHRINK_PERCENT="${MAX_ALLOWED_SHRINK_PERCENT:-0}"
ALLOW_FEED_SHRINK="${ALLOW_FEED_SHRINK:-false}"

USER_AGENT="${USER_AGENT:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36}"

WHOISDS_USERNAME="${WHOISDS_USER:-}"
WHOISDS_PASSWORD="${WHOISDS_PASS:-}"

BASE_URL_FREE="https://whoisds.com/whois-database/newly-registered-domains"

# ============================================================================
# GitHub Actions Context Setup
# ============================================================================
IS_GITHUB_ACTIONS="${GITHUB_ACTIONS:-false}"

if [[ "$IS_GITHUB_ACTIONS" == "true" && -n "$WHOISDS_PASSWORD" ]]; then
    echo "::add-mask::${WHOISDS_PASSWORD}"
fi

# ============================================================================
# Logging & Terminal Output
# ============================================================================
red() {
    printf '\033[31m%s\033[0m\n' "$*" >&2
}

green() {
    printf '\033[32m%s\033[0m\n' "$*"
}

cyan() {
    printf '\033[36m%s\033[0m\n' "$*"
}

yellow() {
    printf '\033[33m%s\033[0m\n' "$*"
}

die() {
    red "FATAL ERROR: $*"
    if [[ "$IS_GITHUB_ACTIONS" == "true" ]]; then
        echo "::error::$*"
    fi
    exit 1
}

# ============================================================================
# Error handling, Signals & Cleanup
# ============================================================================
TEMP_ROOT=""
LOCK_HELD=0

on_error() {
    local exit_code=$?
    local line_no="${BASH_LINENO[0]:-unknown}"
    local cmd="${BASH_COMMAND:-unknown}"
    red "============================================================"
    red "CRITICAL FAILURE in script execution:"
    red "  Exit code: ${exit_code}"
    red "  Line:      ${line_no}"
    red "  Command:   ${cmd}"
    red "============================================================"
    exit "$exit_code"
}

trap on_error ERR

release_lock() {
    if (( LOCK_HELD == 1 )); then
        if command -v flock >/dev/null 2>&1; then
            exec 9>&- 2>/dev/null || true
        fi
        local lock_dir="${LOCK_FILE}.lockdir"
        if [[ -d "$lock_dir" ]]; then
            rm -rf -- "$lock_dir"
        fi
        LOCK_HELD=0
    fi
}

cleanup() {
    local exit_code=$?
    release_lock
    if [[ -n "${TEMP_ROOT:-}" && -d "$TEMP_ROOT" && "$TEMP_ROOT" == */.nrd-work.* ]]; then
        rm -rf -- "$TEMP_ROOT"
    fi
    exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

# ============================================================================
# Date Portability Helper (GNU & BSD Compatibility)
# ============================================================================
DATE_FLAVOR=""
if date -u -d "1 days ago" '+%Y-%m-%d' >/dev/null 2>&1; then
    DATE_FLAVOR="gnu"
elif date -u -v-1d '+%Y-%m-%d' >/dev/null 2>&1; then
    DATE_FLAVOR="bsd"
else
    die "Nepodprt ali manjkajoč 'date' pripomoček."
fi

get_date_days_ago() {
    local days="$1"
    if [[ "$DATE_FLAVOR" == "gnu" ]]; then
        date -u -d "${days} days ago" '+%Y-%m-%d'
    else
        date -u -v-"${days}"d '+%Y-%m-%d'
    fi
}

# ============================================================================
# Locking Mechanism (Local Runner Safety)
# ============================================================================
acquire_lock() {
    local lock_path="$1"
    mkdir -p -m 0700 -- "$(dirname "$lock_path")"

    if command -v flock >/dev/null 2>&1; then
        exec 9>"$lock_path"
        if ! flock -n 9; then
            die "Druga instanca skripte že teče (flock: $lock_path)."
        fi
        LOCK_HELD=1
    else
        local lock_dir="${lock_path}.lockdir"
        if ! mkdir "$lock_dir" 2>/dev/null; then
            local pid=""
            if [[ -f "${lock_dir}/pid" ]]; then
                pid="$(cat "${lock_dir}/pid" 2>/dev/null || true)"
            fi
            if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
                yellow "Odkrit zastarel lock procesa (PID $pid ni aktiven). Čistim..."
                rm -rf -- "$lock_dir"
                if ! mkdir "$lock_dir" 2>/dev/null; then
                    die "Zaklepanje ni uspelo po čiščenju zastarelega locka."
                fi
            else
                die "Druga instanca skripte že teče (PID: ${pid:-neznan}, lockdir: ${lock_dir})."
            fi
        fi
        printf '%s\n' "$$" > "${lock_dir}/pid"
        LOCK_HELD=1
    fi
}

# ============================================================================
# Validation of Required Utilities
# ============================================================================
require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Zahtevani ukaz ni nameščen: $1"
}

for cmd in awk base64 cat curl date grep mktemp mkdir mv rm sort tr gzip; do
    require_command "$cmd"
done

if ! command -v unzip >/dev/null 2>&1; then
    yellow "OPOZORILO: 'unzip' ni nameščen. Če WhoisDS vrne zip arhiv, razpakiranje morda ne bo delovalo."
fi

[[ "$DAY_RANGE" =~ ^[0-9]+$ ]] || die "DAY_RANGE mora biti celo število."
(( DAY_RANGE >= 1 && DAY_RANGE <= 30 )) || die "DAY_RANGE mora biti med 1 in 30."

# ============================================================================
# Directories & Workspace Setup
# ============================================================================
mkdir -p -m 0700 -- "$DAILY_DIR/free"
mkdir -p -m 0700 -- "$DAILY_DIR/paid"
mkdir -p -m 0755 -- "$FEED_DIR"

acquire_lock "$LOCK_FILE"

TEMP_ROOT="$(mktemp -d "${SCRIPT_DIR}/.nrd-work.XXXXXXXX")"
chmod 0700 "$TEMP_ROOT"

TEMP_ALL="${TEMP_ROOT}/all-domains.txt"
TEMP_FILTERED="${TEMP_ROOT}/filtered.txt"
TEMP_HISTORY="${TEMP_ROOT}/history.txt"
TEMP_SORTED="${TEMP_ROOT}/sorted.txt"
TEMP_WHITELIST="${TEMP_ROOT}/whitelist.txt"
: > "$TEMP_ALL"

# ============================================================================
# Crypto / Web3 Detection Regex Engine (Leetspeak, Typosquatting & Deceptions)
# ============================================================================
# 1. Ciljane blagovne znamke s substitucijami (0->o, 1->i, 3->e, 4->a, 5->s) in podvojenimi črkami
CRYPTO_BRANDS='(b[i1l]+n+[a4]+n+c[e3]?|m[e3]+t+[a4]+m+[a4]+s+k|m[e3]+t+[a4]+m+s+k|p+h+[a4]+n+t+[o0]+m|c[o0]+[i1l]+n+b+[a4]+s+[e3]?|t+r+[e3]+z+[o0]+r|l+[e3]+d+g+[e3]+r|u+n+[i1l]+s+w+[a4o]+p|[o0]+p+[e3]+n+s+[e3]+[a4]+|s+[o0]+l+[a4]+n+[a4]+|s+[o0]+l|e+t+h+[e3]+r+[e3]+u+m|e+t+h|p+[o0]+l+y+g+[o0]+n|k+r+[a4]+k+[e3]+n|k+[e3]+p+l+r|[e3]+x+[o0]+d+u+s|r+[a4]+b+b+y|r+[o0]+n+[i1l]+n|[a4]+r+b+[i1l]+t+r+u+m|[o0]+p+t+[i1l]+m+[i1l]+s+m|z+k+-?s+y+n+c|s+u+[i1l]+|[a4]+p+t+[o0]+s|t+r+u+s+t+-?w+[a4]+l+l+[e3]+t|p+r+[o0]+t+[o0]+n|m+[e3]+t+[a4]+)'

# 2. Splošni Web3 / Kripto izrazi z leetspeakom
CRYPTO_TERMS='(c+r+[y|i|1]+p+t+[o0]+|w+[a4]+l+l+[e3]+t+[s]?|v+v+a+l+l+e+t|w+[e3]+b+3|v+v+e+b+3|d+[e3]+f+[i1l]+|d+[e3]+x|s+w+[a4]+p|s+t+[a4]+k+[e3]+|s+t+[a4]+k+[i1l]+n+g|m+[i1l]+n+t|m+[i1l]+n+t+[i1l]+n+g|t+[o0]+k+[e3]+n+[s]?|n+f+t+[s]?)'

# 3. Phishing akcije in vabljivi izrazi (Combosquatting)
ACTION_HOOKS='([a4][i1l]r-?dr[o0]p|cl[a4][i1l]m[s]?|cl[a4][i1l]m[i1l]ng|l[o0]g[i1l]n|s[i1l]gn[i1l]n|[a4]uth|v[e3]r[i1l]fy|v[e3]r[i1l]f[i1l]c[a4]t[i1l][o0]n|c[o0]nn[e3]ct|sync|s[e3]cur[e3]|s[e3]cur[i1l]ty|supp[o0]rt|h[e3]lp|r[e3]w[a4]rd[s]?|pr[o0]m[o0]|b[o0]nus|m[i1l]gr[a4]t[e3]|upd[a4]t[e3]|v[a4]ult|br[i1l]dg[e3]|r[e3]s[o0]lv[e3]|n[o0]d[e3]|kyc)'

DETECTION_REGEX="(^|[.-])(${CRYPTO_BRANDS}|${CRYPTO_TERMS})([.-]|$)"
COMBO_REGEX="(^|[.-])(${CRYPTO_BRANDS}|${CRYPTO_TERMS}).*(${ACTION_HOOKS})|(${ACTION_HOOKS}).*(${CRYPTO_BRANDS}|${CRYPTO_TERMS})([.-]|$)"
PUNYCODE_REGEX='(^|\.)xn--'

WHITELIST_REGEX='(^|\.)(binance\.com|metamask\.io|uniswap\.org|ethereum\.org|polygon\.technology|proton\.me|ledger\.com|kraken\.com|coinbase\.com|opensea\.io|solana\.com|meta\.com|trezor\.io|exodus\.com|arbitrum\.io|optimism\.io|zksync\.io|keplr\.app|rabby\.io|trustwallet\.com|sui\.io|aptoslabs\.com)$'

# Compile external whitelist if provided
: > "$TEMP_WHITELIST"
if [[ -n "$WHITELIST_FILE" && -f "$WHITELIST_FILE" ]]; then
    cyan "Nalagam zunanji whitelist: ${WHITELIST_FILE}"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$WHITELIST_FILE" |
        tr '[:upper:]' '[:lower:]' |
        sed -E 's#^[[:space:]]+##; s#[[:space:]]+$##; s#^\.+##; s#\.+$##' |
        sort -u >> "$TEMP_WHITELIST"
fi

# ============================================================================
# Domain Extraction & RFC Validation Engine (100% mawk / gawk / nawk Compatible)
# OPOMBA: Strogo BREZ {n,} intervalnih izrazov v AWK!
# ============================================================================
extract_and_validate_domains() {
    awk '
    {
        sub(/^[[:space:]]*#.*$/, "")
        if ($0 ~ /^[[:space:]]*$/) next

        # Čiščenje ločil in narekovajev v CSV / logih
        gsub(/[\r\n\t,;"]/, " ")
        gsub(/\047/, " ")

        for (i = 1; i <= NF; i++) {
            token = $i

            # Odstrani protokole, poti, vrata
            sub(/^https?:\/\//, "", token)
            sub(/\/.*$/, "", token)
            sub(/:[0-9]+$/, "", token)

            # Odstrani začetne/končne pike ter pretvori v male črke
            sub(/^\.+/, "", token)
            sub(/\.+$/, "", token)
            token = tolower(token)

            # Preverjanje dolžine in dovoljenih znakov
            if (length(token) < 4 || length(token) > 253) continue
            if (token !~ /\./) continue
            if (token ~ /\.\./) continue
            if (token !~ /^[a-z0-9.-]+$/) continue
            if (token ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) continue

            n = split(token, labels, ".")
            if (n < 2) continue

            valid = 1
            for (j = 1; j <= n; j++) {
                lbl = labels[j]
                len = length(lbl)
                if (len < 1 || len > 63) { valid = 0; break }
                if (lbl ~ /^-/ || lbl ~ /-$/) { valid = 0; break }
                
                # TLD preverba: dolžina >= 2, samo črke ali punycode xn--
                # BREZ {2,} INTERVALA! Uporabljena len + preprost plus regex.
                if (j == n) {
                    if (len < 2) { valid = 0; break }
                    if (lbl ~ /^[0-9]+$/) { valid = 0; break }
                    if (lbl !~ /^[a-z]+$/ && lbl !~ /^xn--[a-z0-9]+$/) { valid = 0; break }
                }
            }

            if (valid) {
                print token
                break
            }
        }
    }'
}

# ============================================================================
# Safe Decompression (Zip-Slip Immune Streaming)
# ============================================================================
decompress_archive() {
    local input_archive="$1"
    local output_txt="$2"

    [[ -s "$input_archive" ]] || {
        red "Arhiv je prazen ali ne obstaja: $input_archive"
        return 1
    }

    if grep -qiE '^(<!DOCTYPE|<html|<head|<body|<error)' "$input_archive" 2>/dev/null; then
        red "Napaka: Prenesena vsebina je HTML (verjetno Cloudflare ali napaka strežnika)."
        return 1
    fi

    local magic_bytes
    magic_bytes="$(head -c 4 "$input_archive" 2>/dev/null || true)"

    if [[ "$magic_bytes" == PK* ]]; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -p "$input_archive" > "$output_txt"
        else
            red "ZIP arhiv zaznan, vendar 'unzip' ni na voljo."
            return 1
        fi
    elif [[ "$(printf '%s' "$magic_bytes" | od -An -tx1 2>/dev/null | tr -d ' \n')" == 1f8b* ]]; then
        gzip -dc "$input_archive" > "$output_txt"
    else
        if command -v unzip >/dev/null 2>&1 && unzip -p "$input_archive" > "$output_txt" 2>/dev/null; then
            return 0
        elif gzip -dc "$input_archive" > "$output_txt" 2>/dev/null; then
            return 0
        elif [[ -s "$input_archive" ]]; then
            cat "$input_archive" > "$output_txt"
        else
            red "Neznan format arhiva."
            return 1
        fi
    fi
}

# ============================================================================
# Secure Curl Download (No Credentials in Process Table / Logs)
# ============================================================================
secure_download() {
    local url="$1"
    local target_archive="$2"
    local cfg="${TEMP_ROOT}/curl_cfg.$$"
    local err_file="${TEMP_ROOT}/curl_err.$$"

    cat > "$cfg" <<EOF
url = "${url}"
user-agent = "${USER_AGENT}"
proto = "=https"
tlsv1.2
connect-timeout = 25
max-time = 300
retry = 3
retry-delay = 3
fail
silent
show-error
location
EOF
    chmod 0600 "$cfg"

    if ! curl --config "$cfg" --output "$target_archive" 2>"$err_file"; then
        local err_msg
        err_msg="$(cat "$err_file" 2>/dev/null || true)"
        if [[ -n "${WHOISDS_PASSWORD:-}" ]]; then
            err_msg="${err_msg//"$WHOISDS_PASSWORD"/[REDACTED]}"
        fi
        rm -f "$cfg" "$err_file"
        red "Prenos ni uspel: ${err_msg:-neznana napaka}"
        return 1
    fi

    rm -f "$cfg" "$err_file"
    [[ -s "$target_archive" ]] || return 1
}

# ============================================================================
# Feed Retrieval Logic
# ============================================================================
download_free() {
    local date="$1"
    local output="$2"
    local encoded
    encoded="$(printf '%s' "${date}.zip" | base64 | tr -d '\r\n=' )"
    local url="${BASE_URL_FREE}/${encoded}/nrd"
    local archive="${TEMP_ROOT}/free_${date}.archive"

    cyan "Downloading FREE NRD: ${date}"
    if ! secure_download "$url" "$archive"; then
        if [[ "$STRICT_DOWNLOAD" == "true" ]]; then
            die "FREE NRD prenos ni uspel: ${date}"
        else
            yellow "OPOZORILO: FREE NRD za ${date} ni na voljo. Nadaljujem..."
            return 1
        fi
    fi

    if ! decompress_archive "$archive" "$output"; then
        rm -f "$archive"
        die "Dekompresija FREE NRD ni uspela: ${date}"
    fi
    rm -f "$archive"
    [[ -s "$output" ]] || die "FREE NRD datoteka je prazna: ${date}"
}

download_paid() {
    local date="$1"
    local output="$2"
    [[ -n "$WHOISDS_USERNAME" && -n "$WHOISDS_PASSWORD" ]] || die "Paid poverilnice niso nastavljene."

    local url="https://whoisds.com/your-download/direct-download_file/${WHOISDS_USERNAME}/${WHOISDS_PASSWORD}/${date}.zip/ddu"
    local archive="${TEMP_ROOT}/paid_${date}.archive"

    cyan "Downloading PAID NRD: ${date}"
    if ! secure_download "$url" "$archive"; then
        if [[ "$STRICT_DOWNLOAD" == "true" ]]; then
            die "PAID NRD prenos ni uspel: ${date}"
        else
            yellow "OPOZORILO: PAID NRD za ${date} ni na voljo. Nadaljujem..."
            return 1
        fi
    fi

    if ! decompress_archive "$archive" "$output"; then
        rm -f "$archive"
        die "Dekompresija PAID NRD ni uspela: ${date}"
    fi
    rm -f "$archive"
    [[ -s "$output" ]] || die "PAID NRD datoteka je prazna: ${date}"
}

process_type() {
    local type="$1"
    local i="$DAY_RANGE"
    local type_dir="${DAILY_DIR}/${type}"

    while (( i > 0 )); do
        local date
        date="$(get_date_days_ago "$i")"
        local cached="${type_dir}/${date}"
        local downloaded="${TEMP_ROOT}/${type}-${date}.txt"

        if [[ -s "$cached" ]]; then
            cyan "${cached} že obstaja - uporabljam cache."
            cat "$cached" >> "$TEMP_ALL"
        else
            local status=0
            if [[ "$type" == "free" ]]; then
                download_free "$date" "$downloaded" || status=1
            else
                download_paid "$date" "$downloaded" || status=1
            fi

            if (( status == 0 )) && [[ -s "$downloaded" ]]; then
                local tmp_cached
                tmp_cached="$(mktemp "${type_dir}/.cache.tmp.XXXXXXXX")"
                cp -- "$downloaded" "$tmp_cached"
                chmod 0600 "$tmp_cached"
                mv -f -- "$tmp_cached" "$cached"
                cat "$cached" >> "$TEMP_ALL"
            fi
        fi
        (( i-- ))
    done
}

# ============================================================================
# Main Execution Flow
# ============================================================================
green "============================================================"
green "HackProtect Labs | Crypto NRD Threat Feed (GitHub Edition)"
green "============================================================"

# Preberi velikost obstoječega feeda za Shrink Guard
PREV_FEED_COUNT=0
if [[ -f "$OUTPUT_FEED" ]]; then
    PREV_FEED_COUNT="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$OUTPUT_FEED" | wc -l | tr -d ' ')"
    cyan "Obstoječa zgodovinska baza domen: ${PREV_FEED_COUNT} indikatorjev"
fi

# Obdelaj Free Feed
process_type "free"

# Obdelaj Paid Feed če obstajajo poverilnice
if [[ -n "$WHOISDS_USERNAME" && -n "$WHOISDS_PASSWORD" ]]; then
    green "WhoisDS paid poverilnice zaznane."
    process_type "paid"
else
    yellow "WhoisDS paid poverilnice niso nastavljene - preskakujem paid feed."
fi

# ============================================================================
# Filtriranje in zaznava phishing indikatorjev
# ============================================================================
cyan "Normaliziram in filtriram domene (blagovne znamke, leetspeak, zavajanja)..."

if [[ -s "$TEMP_ALL" ]]; then
    extract_and_validate_domains < "$TEMP_ALL" |
        grep -Evi "$WHITELIST_REGEX" |
        grep -Ei "${DETECTION_REGEX}|${COMBO_REGEX}|${PUNYCODE_REGEX}" |
        sort -u > "$TEMP_FILTERED"
else
    : > "$TEMP_FILTERED"
fi

# Uveljavi zunanji whitelist na novih kandidatih
if [[ -s "$TEMP_WHITELIST" && -s "$TEMP_FILTERED" ]]; then
    grep -F -v -x -f "$TEMP_WHITELIST" "$TEMP_FILTERED" > "${TEMP_FILTERED}.tmp" || true
    mv -f -- "${TEMP_FILTERED}.tmp" "$TEMP_FILTERED"
fi

FILTERED_TODAY="$(wc -l < "$TEMP_FILTERED" | tr -d ' ')"
cyan "Novih odkritih potencialnih phishing kandidatov: ${FILTERED_TODAY}"

# ============================================================================
# Strictly Append-Only Historical Merging
# ============================================================================
if [[ -f "$OUTPUT_FEED" ]]; then
    cyan "Nalagam obstoječi zgodovinski feed (append-only način)..."
    extract_and_validate_domains < "$OUTPUT_FEED" > "$TEMP_HISTORY"

    # Če se posodobi zunanji whitelist, se izločijo lažni pozitivi
    if [[ -s "$TEMP_WHITELIST" && -s "$TEMP_HISTORY" ]]; then
        grep -F -v -x -f "$TEMP_WHITELIST" "$TEMP_HISTORY" > "${TEMP_HISTORY}.tmp" || true
        mv -f -- "${TEMP_HISTORY}.tmp" "$TEMP_HISTORY"
    fi
else
    : > "$TEMP_HISTORY"
fi

# Združi današnje ugotovitve z zgodovinsko bazo (append-only)
cat "$TEMP_FILTERED" "$TEMP_HISTORY" | sort -u > "$TEMP_SORTED"

TOTAL_DOMAINS="$(wc -l < "$TEMP_SORTED" | tr -d ' ')"
UTC_NOW="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ============================================================================
# SHRINK GUARD: Preprečevanje nehotenega brisanja ali okrnitve baze
# ============================================================================
if (( PREV_FEED_COUNT > 0 && TOTAL_DOMAINS < PREV_FEED_COUNT )); then
    LOST_COUNT=$(( PREV_FEED_COUNT - TOTAL_DOMAINS ))
    LOST_PERCENT=$(( (LOST_COUNT * 100) / PREV_FEED_COUNT ))

    if [[ "$ALLOW_FEED_SHRINK" != "true" && $LOST_PERCENT -gt $MAX_ALLOWED_SHRINK_PERCENT ]]; then
        red "============================================================"
        red "🛑 SHRINK GUARD TRIGGERED: Zaznana nevarna izguba baze podatkov!"
        red "  Prejšnje število domen: ${PREV_FEED_COUNT}"
        red "  Novo število domen:     ${TOTAL_DOMAINS}"
        red "  Izguba:                 ${LOST_COUNT} domen (${LOST_PERCENT}%)"
        red "  Dovoljena izguba:       ${MAX_ALLOWED_SHRINK_PERCENT}%"
        red "Prekinjam izvajanje. Obstoječi feed (${OUTPUT_FEED}) ostaja NESPREMENJEN!"
        red "============================================================"
        die "Shrink Guard je ustavil posodobitev zaradi okrnjene baze."
    else
        yellow "OPOZORILO: Število domen se je zmanjšalo (${PREV_FEED_COUNT} -> ${TOTAL_DOMAINS}) - verjetno zaradi posodobitve whitelista."
    fi
fi

if (( TOTAL_DOMAINS == 0 )) && (( PREV_FEED_COUNT > 0 )); then
    die "Varnostna prekinitev: Končni seznam je prazen, obstoječi feed pa vsebuje podatke. Zavračam prepis z 0 domenami."
fi

# ============================================================================
# Resnično atomarna zamenjava datoteke (Isti datotečni sistem)
# ============================================================================
FEED_DIR_PATH="$(dirname "$OUTPUT_FEED")"
mkdir -p -m 0755 -- "$FEED_DIR_PATH"
TEMP_FEED_FILE="$(mktemp "${FEED_DIR_PATH}/.feed.tmp.XXXXXXXX")"

cat > "$TEMP_FEED_FILE" <<EOF
# =====================================================================
# Feed Name: Crypto NRD Threat Feed
# Maintainer: HackProtect Labs (@HackProtectLabs)
# Classification: TLP:CLEAR
# Last Updated: ${UTC_NOW}
# Total Active Domains: ${TOTAL_DOMAINS}
# Repository: https://github.com/HackProtect-Labs/crypto-nrd-feed
# Description: Automated CTI feed tracking newly registered domains associated with
#              Web3/Crypto phishing, impersonation, typosquatting & leetspeak indicators.
# Retention: Historical accumulation enabled (strictly append-only).
# =====================================================================
EOF

cat "$TEMP_SORTED" >> "$TEMP_FEED_FILE"
chmod 0644 "$TEMP_FEED_FILE"
mv -f -- "$TEMP_FEED_FILE" "$OUTPUT_FEED"

# ============================================================================
# Post-Generation Integrity Verification
# ============================================================================
[[ -s "$OUTPUT_FEED" ]] || die "Končni feed je prazen."
grep -q '^# Feed Name: Crypto NRD Threat Feed$' "$OUTPUT_FEED" || die "Validacija glave feeda ni uspela."

COUNT_IN_FEED="$(grep -vE '^#|^[[:space:]]*$' "$OUTPUT_FEED" | wc -l | tr -d ' ')"
if [[ "$COUNT_IN_FEED" -ne "$TOTAL_DOMAINS" ]]; then
    die "Integriteta feeda ni skladna: glava trdi ${TOTAL_DOMAINS}, dejanskih vrstic domen pa je ${COUNT_IN_FEED}."
fi

FEED_CHANGED="false"
NET_NEW=$(( TOTAL_DOMAINS - PREV_FEED_COUNT ))
if (( NET_NEW > 0 )); then
    FEED_CHANGED="true"
fi

green "============================================================"
green "Feed successfully updated & verified."
green "============================================================"
green "Previous total:       ${PREV_FEED_COUNT}"
green "New detections today: ${FILTERED_TODAY}"
green "Net new added:        ${NET_NEW}"
green "Historical total:     ${TOTAL_DOMAINS}"
green "Feed path:            ${OUTPUT_FEED}"
green "Updated at:           ${UTC_NOW}"
green "Validation OK."

# ============================================================================
# GitHub Actions Integracija (Step Summary & Outputs)
# ============================================================================
if [[ "$IS_GITHUB_ACTIONS" == "true" ]]; then
    if [[ -n "${GITHUB_OUTPUT:-}" && -f "$GITHUB_OUTPUT" ]]; then
        {
            echo "domains_added=${FILTERED_TODAY}"
            echo "net_new=${NET_NEW}"
            echo "total_domains=${TOTAL_DOMAINS}"
            echo "feed_changed=${FEED_CHANGED}"
            echo "updated_at=${UTC_NOW}"
        } >> "$GITHUB_OUTPUT"
    fi

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$GITHUB_STEP_SUMMARY" ]]; then
        cat >> "$GITHUB_STEP_SUMMARY" <<EOF
### 🛡️ Crypto NRD Threat Feed Update Summary

| Metrika | Vrednost |
| :--- | :--- |
| **Status** | ✅ Uspešno posodobljeno (Append-only) |
| **Nove detekcije danes** | \`${FILTERED_TODAY}\` |
| **Neto dodanih domen** | \`+${NET_NEW}\` |
| **Skupno v bazi (Historical)** | \`${TOTAL_DOMAINS}\` |
| **Sprememba baze** | \`${FEED_CHANGED}\` |
| **Shrink Guard status** | 🛡️ Zaščiteno (0% nedovoljenih izgub) |
| **Čas posodobitve** | \`${UTC_NOW}\` |
| **Pot datoteke** | \`${OUTPUT_FEED}\` |

EOF
    fi
fi
