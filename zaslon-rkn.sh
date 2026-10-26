#!/usr/bin/env bash
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
  echo "bash 4.4+ required / нужен bash 4.4+" >&2
  exit 1
fi
set -Eeuo pipefail
umask 022

readonly ZS_NAME="zaslon-rkn"
readonly ZS_VERSION="1.0.0"
readonly ZS_URL="https://github.com/0fells/zaslon"
readonly ZS_TABLE="zaslon_rkn"
readonly ZS_CHAIN="ZASLON_RKN"
readonly ZS_SET="zrkn"
readonly ZS_BIN="/usr/local/sbin/${ZS_NAME}"
readonly ZS_CONF="${ZASLON_CONF:-/etc/zaslon/rkn.conf}"
readonly ZS_STATE="${ZASLON_STATE:-/var/lib/zaslon/rkn}"
readonly ZS_LOCK="/run/${ZS_NAME}.lock"
readonly ZS_UNIT_DIR="/etc/systemd/system"
readonly ZS_CRON="/etc/cron.d/${ZS_NAME}"

UI_LANG=""
BACKEND="auto"
IPV6=1
LOG_DROPS=0
LOG_RATE="10/minute"
BAD_TCP_FLAGS=1
DROP_PING=0
AUTO_WHITELIST_LOCAL=1
MIN_PREFIX4=8
MIN_PREFIX6=19
DOWNLOAD_TIMEOUT=60
ASN_CACHE_HOURS=24
UPDATE_CALENDAR="*-*-* 00/6:17:00"
SOURCES=(
  "plain https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt"
  "plain https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v6.txt"
)
ASNS=(61280)
STATIC_NETS=("85.142.100.0/24")
WHITELIST=()

DRY_RUN=0
CACHED_ONLY=0
PURGE=0
WORK=""

declare -A MSG_RU=() MSG_EN=()
m() { MSG_RU[$1]=$2; MSG_EN[$1]=$3; }

m need_root      "Нужны права root: запустите через sudo." \
                 "Root privileges required: run with sudo."
m no_backend     "Не найден ни nftables (nft), ни iptables + ipset. Установите nftables." \
                 "Neither nftables (nft) nor iptables + ipset found. Install nftables."
m no_fetcher     "Нужен curl или wget." \
                 "curl or wget is required."
m bad_backend    "Неизвестный BACKEND: %s (ожидается auto, nft или iptables)." \
                 "Unknown BACKEND: %s (expected auto, nft or iptables)."
m busy           "Другой экземпляр %s уже работает." \
                 "Another instance of %s is already running."
m unknown_cmd    "Неизвестная команда: %s. Справка: %s help" \
                 "Unknown command: %s. Help: %s help"
m bad_ip         "Это не IP-адрес или подсеть: %s" \
                 "Not an IP address or network: %s"
m conf_created   "Создан конфиг %s" \
                 "Config created: %s"
m conf_kept      "Конфиг %s уже есть, оставлен без изменений." \
                 "Config %s already exists, left untouched."
m wl_ssh         "Ваш IP %s добавлен в белый список, чтобы не потерять доступ по SSH." \
                 "Your IP %s was whitelisted so you keep SSH access."
m src_ok         "  [+] %-7s %6s  %s" \
                 "  [+] %-7s %6s  %s"
m src_cache      "  [~] %-7s %6s  %s (не скачалось, взят кэш)" \
                 "  [~] %-7s %6s  %s (download failed, using cache)"
m src_fail       "  [-] %-7s %6s  %s (не скачалось, кэша нет)" \
                 "  [-] %-7s %6s  %s (download failed, no cache)"
m src_empty      "  [~] %-7s %6s  %s (пустой ответ, взят кэш)" \
                 "  [~] %-7s %6s  %s (empty response, using cache)"
m fetching       "Загрузка списков..." \
                 "Downloading lists..."
m asn_progress   "ASN: %s из %s" \
                 "ASN: %s of %s"
m built          "Собрано: IPv4 %s, IPv6 %s подсетей." \
                 "Built: IPv4 %s, IPv6 %s networks."
m empty_lists    "Списки пусты: правила не меняю, чтобы не снять защиту по ошибке." \
                 "Lists are empty: rules left unchanged so protection is not dropped by mistake."
m no_cache       "Нет сохранённых списков. Сначала выполните: %s update" \
                 "No saved lists. Run first: %s update"
m applied        "Правила применены (%s): IPv4 %s, IPv6 %s, белый список %s." \
                 "Rules applied (%s): IPv4 %s, IPv6 %s, whitelist %s."
m stopped        "Защита снята, правила %s удалены." \
                 "Protection disabled, %s rules removed."
m installed      "Установлено. Обновление списков по расписанию: %s" \
                 "Installed. Scheduled list updates: %s"
m installed_cron "Установлено без systemd: обновление через cron каждые 6 часов." \
                 "Installed without systemd: cron updates every 6 hours."
m uninstalled    "Удалено. Конфиг и кэш: %s" \
                 "Uninstalled. Config and cache: %s"
m purged         "Удалено вместе с конфигом и кэшем." \
                 "Uninstalled together with config and cache."
m dry_run        "Пробный запуск: правила ниже НЕ применены." \
                 "Dry run: the rules below were NOT applied."
m st_title       "%s %s" \
                 "%s %s"
m st_backend     "Бэкенд:            %s" \
                 "Backend:           %s"
m st_active      "Защита:            %s" \
                 "Protection:        %s"
m st_on          "включена" \
                 "enabled"
m st_off         "выключена" \
                 "disabled"
m st_counts      "В списках:         IPv4 %s, IPv6 %s" \
                 "Listed:            IPv4 %s, IPv6 %s"
m st_updated     "Обновлено:         %s" \
                 "Updated:           %s"
m st_never       "никогда" \
                 "never"
m st_timer       "Таймер обновления: %s" \
                 "Update timer:      %s"
m st_dropped     "Отброшено:         %s пакетов, %s байт" \
                 "Dropped:           %s packets, %s bytes"
m st_dropped_by  "  %-16s %12s пакетов" \
                 "  %-16s %12s packets"
m ck_in          "%s ЕСТЬ в блок-листе." \
                 "%s IS in the block list."
m ck_out         "%s нет в блок-листе." \
                 "%s is not in the block list."
m ck_wl          "%s в белом списке, не блокируется." \
                 "%s is whitelisted and never blocked."
m ck_src         "  найден в: %s (%s)" \
                 "  found in: %s (%s)"
m added          "%s добавлен в %s." \
                 "%s added to %s."
m removed        "%s удалён из %s." \
                 "%s removed from %s."
m not_found      "%s не найден в %s." \
                 "%s not found in %s."
m report_none    "Записей о блокировках нет. Включите LOG_DROPS=1 в %s." \
                 "No drop records. Set LOG_DROPS=1 in %s."
m report_title   "Самые активные заблокированные источники:" \
                 "Most active blocked sources:"
m port_skip      "Порт %s занят службой, ловушка на нём не ставится." \
                 "Port %s is used by a service, no trap there."

m usage "Использование: %s [--lang ru|en] [--dry-run] <команда> [аргументы]

Защищает сервер от зондов и сканеров РКН, ГРЧЦ, НКЦКИ, CyberOK и подсетей
госорганов: новые входящие соединения с них отбрасываются молча, сервер для
них выглядит выключенным. Исходящие соединения и ответы на них не трогаются.

Команды:
  install            установить в %s, создать конфиг, включить автообновление
  update             скачать списки и применить правила
  apply [--cached]   применить правила из сохранённых списков
  stop               снять правила (до следующего apply или перезагрузки)
  status             состояние, размеры списков, счётчики отброшенных пакетов
  check <IP>         проверить, заблокирован ли адрес и из какого он списка
  ban <IP/сеть>      добавить свой адрес или подсеть в блок-лист
  unban <IP/сеть>    убрать адрес из своего блок-листа
  allow <IP/сеть>    добавить в белый список
  disallow <IP/сеть> убрать из белого списка
  report [N]         топ-N заблокированных источников по журналу (LOG_DROPS=1)
  uninstall [--purge] удалить (с --purge также конфиг и кэш)
  version            версия

Конфиг: %s
Проект: %s" \
"Usage: %s [--lang ru|en] [--dry-run] <command> [args]

Protects a server from probes and scanners of Roskomnadzor (RKN), GRCHC,
NKCKI, CyberOK and Russian government networks: new inbound connections from
them are silently dropped, so the server looks switched off to them. Outbound
connections and their replies are left alone.

Commands:
  install            install to %s, create config, enable auto-updates
  update             download lists and apply rules
  apply [--cached]   apply rules from saved lists
  stop               remove rules (until the next apply or reboot)
  status             state, list sizes, dropped packet counters
  check <IP>         tell whether an address is blocked and by which list
  ban <IP/net>       add your own address or network to the block list
  unban <IP/net>     remove an address from your block list
  allow <IP/net>     add to the whitelist
  disallow <IP/net>  remove from the whitelist
  report [N]         top N blocked sources from the log (LOG_DROPS=1)
  uninstall [--purge] remove (with --purge also config and cache)
  version            version

Config: %s
Project: %s"

tr_() {
  if [[ $UI_LANG == ru ]]; then
    printf '%s' "${MSG_RU[$1]:-$1}"
  else
    printf '%s' "${MSG_EN[$1]:-$1}"
  fi
}

say() {
  local fmt
  fmt=$(tr_ "$1")
  shift
  printf "${fmt}\n" "$@"
}

c_red="" c_grn="" c_yel="" c_dim="" c_off=""
if [[ -t 1 ]]; then
  c_red=$'\e[31m' c_grn=$'\e[32m' c_yel=$'\e[33m' c_dim=$'\e[2m' c_off=$'\e[0m'
fi

info() { printf '%s' "$c_grn"; say "$@"; printf '%s' "$c_off"; }
warn() { printf '%s' "$c_yel" >&2; say "$@" >&2; printf '%s' "$c_off" >&2; }
die()  { printf '%s' "$c_red" >&2; say "$@" >&2; printf '%s' "$c_off" >&2; exit 1; }
note() { command -v logger >/dev/null 2>&1 && logger -t "$ZS_NAME" -- "$*" || true; }

detect_lang() {
  local l="${ZASLON_LANG:-${UI_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}}"
  case "$l" in
    ru*|RU*) UI_LANG=ru ;;
    *) UI_LANG=en ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

need_root() { [[ $EUID -eq 0 ]] || (( DRY_RUN )) || die need_root; }

load_config() {
  if [[ -r $ZS_CONF ]]; then
    . "$ZS_CONF"
  fi
}

pick_backend() {
  case "$BACKEND" in
    auto)
      if have nft; then BACKEND=nft
      elif have iptables && have ipset; then BACKEND=iptables
      elif (( DRY_RUN )); then BACKEND=nft
      else die no_backend
      fi ;;
    nft) have nft || (( DRY_RUN )) || die no_backend ;;
    iptables) { have iptables && have ipset; } || (( DRY_RUN )) || die no_backend ;;
    *) die bad_backend "$BACKEND" ;;
  esac
}

take_lock() {
  (( DRY_RUN )) && return 0
  have flock || return 0
  exec 9>"$ZS_LOCK"
  flock -w 300 9 || die busy "$ZS_NAME"
}

release_lock() {
  { exec 9>&-; } 2>/dev/null || true
}

cleanup() { [[ -n $WORK && -d $WORK ]] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

fetch() {
  local url=$1 out=$2
  if have curl; then
    curl -fsSL --retry 2 --retry-delay 3 --connect-timeout 15 --max-time "$DOWNLOAD_TIMEOUT" \
      -A "${ZS_NAME}/${ZS_VERSION} (+${ZS_URL})" -o "$out" "$url" 2>/dev/null
  elif have wget; then
    wget -q -T "$DOWNLOAD_TIMEOUT" -t 3 -U "${ZS_NAME}/${ZS_VERSION} (+${ZS_URL})" -O "$out" "$url"
  else
    die no_fetcher
  fi
}

extract_plain() { sed -e 's/[#;].*//' | awk 'NF { print $1 }'; }
extract_dshield() { awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /^[0-9]+$/ { print $1 "/" $3 }'; }
extract_json() { grep -oE '"(cidr|prefix)" *: *"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/'; }

normalize() {
  local out4=$1 out6=$2
  : >"$out4"
  : >"$out6"
  awk -v min4="$MIN_PREFIX4" -v min6="$MIN_PREFIX6" -v strict="${NORM_STRICT:-1}" \
      -v out4="$out4" -v out6="$out6" '
    function hexval(h,   i, c, v) {
      v = 0; h = tolower(h)
      for (i = 1; i <= length(h); i++) {
        c = index("0123456789abcdef", substr(h, i, 1))
        if (!c) return -1
        v = v * 16 + c - 1
      }
      return v
    }
    function v4int(a,   o, n, i, v) {
      n = split(a, o, ".")
      if (n != 4) return -1
      v = 0
      for (i = 1; i <= 4; i++) {
        if (o[i] !~ /^[0-9]+$/ || length(o[i]) > 3 || o[i] + 0 > 255) return -1
        v = v * 256 + o[i]
      }
      return v
    }
    function v4str(v) {
      return sprintf("%d.%d.%d.%d", int(v / 16777216) % 256, int(v / 65536) % 256, int(v / 256) % 256, v % 256)
    }
    function reserved4(s, e,   i) {
      for (i = 1; i <= nres; i++)
        if (s <= rend[i] && rstart[i] <= e) return 1
      return 0
    }
    function addres(cidr,   a, p) {
      split(cidr, a, "/"); p = a[2] + 0
      nres++
      rstart[nres] = v4int(a[1])
      rend[nres] = rstart[nres] + 2 ^ (32 - p) - 1
    }
    function v6norm(addr, p,   dc, head, tail, nh, nt, H, T, hx, k, i, v, b, blk, out) {
      if (addr ~ /[^0-9a-fA-F:]/ || addr !~ /:/) return ""
      dc = index(addr, "::")
      if (dc) {
        head = substr(addr, 1, dc - 1); tail = substr(addr, dc + 2)
        if (index(tail, "::")) return ""
      } else { head = addr; tail = "" }
      nh = (head == "") ? 0 : split(head, H, ":")
      nt = (tail == "") ? 0 : split(tail, T, ":")
      if (dc) { if (nh + nt > 7) return "" } else if (nh != 8) return ""
      k = 0
      for (i = 1; i <= nh; i++) hx[++k] = H[i]
      if (dc) for (i = 1; i <= 8 - nh - nt; i++) hx[++k] = "0"
      for (i = 1; i <= nt; i++) hx[++k] = T[i]
      out = ""
      for (i = 1; i <= 8; i++) {
        if (length(hx[i]) < 1 || length(hx[i]) > 4) return ""
        v = hexval(hx[i]); if (v < 0) return ""
        b = p - (i - 1) * 16
        if (b <= 0) v = 0
        else if (b < 16) { blk = 2 ^ (16 - b); v = int(v / blk) * blk }
        W[i] = v
        out = out (i > 1 ? ":" : "") sprintf("%x", v)
      }
      return out
    }
    BEGIN {
      nres = 0
      split("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3", R, " ")
      for (i in R) addres(R[i])
    }
    {
      gsub(/\r/, "")
      x = $1
      if (x == "") next
      n = split(x, parts, "/")
      if (n > 2) next
      addr = parts[1]
      if (index(addr, ":")) {
        p = (n == 2) ? parts[2] : 128
        if (p !~ /^[0-9]+$/ || p + 0 > 128 || p + 0 < min6) next
        p += 0
        a6 = v6norm(addr, p)
        if (a6 == "") next
        if (strict && (W[1] < 8192 || W[1] > 16383)) next
        if (strict && W[1] == 8193 && W[2] == 3512) next
        print a6 "/" p > out6
      } else {
        p = (n == 2) ? parts[2] : 32
        if (p !~ /^[0-9]+$/ || p + 0 > 32 || p + 0 < min4) next
        p += 0
        v = v4int(addr)
        if (v < 0) next
        blk = 2 ^ (32 - p)
        s = int(v / blk) * blk
        if (strict && reserved4(s, s + blk - 1)) next
        print v4str(s) "/" p > out4
      }
    }
  '
}

normalize_loose() { MIN_PREFIX4=1 MIN_PREFIX6=1 NORM_STRICT=0 normalize "$@"; }

norm_one() {
  local f4 f6
  f4=$(mktemp) f6=$(mktemp)
  printf '%s\n' "$1" | normalize_loose "$f4" "$f6"
  cat "$f4" "$f6"
  rm -f "$f4" "$f6"
}

is_ip() { [[ -n $1 && -n $(norm_one "$1") ]]; }

src_key() { printf '%s' "$1" | cksum | awk '{print $1}'; }

file_age_hours() {
  local f=$1 now mt
  [[ -f $f ]] || { echo 999999; return; }
  now=$(date +%s)
  mt=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  echo $(( (now - mt) / 3600 ))
}

count_lines() { if [[ -s $1 ]]; then wc -l <"$1" | tr -d ' '; else echo 0; fi; }

pull_source() {
  local fmt=$1 url=$2 label=$3 cache tmp n
  cache="$ZS_STATE/cache/$(src_key "$url").lst"
  tmp="$WORK/dl"
  if (( CACHED_ONLY )); then
    [[ -f $cache ]] && cat "$cache" >>"$WORK/tokens"
    return 0
  fi
  if fetch "$url" "$tmp"; then
    "extract_${fmt}" <"$tmp" >"$WORK/tok" || true
    if [[ -s $WORK/tok ]]; then
      mv "$WORK/tok" "$cache"
      printf '%s\n' "$url" >"$cache.src"
      say src_ok "$fmt" "$(count_lines "$cache")" "$label"
    elif [[ -f $cache ]]; then
      say src_empty "$fmt" "$(count_lines "$cache")" "$label"
    else
      say src_fail "$fmt" 0 "$label"
    fi
  elif [[ -f $cache ]]; then
    say src_cache "$fmt" "$(count_lines "$cache")" "$label"
  else
    say src_fail "$fmt" 0 "$label"
  fi
  [[ -f $cache ]] && cat "$cache" >>"$WORK/tokens"
  return 0
}

pull_asn() {
  local asn=${1#AS} cache url
  asn=${asn#as}
  [[ $asn =~ ^[0-9]+$ ]] || return 0
  cache="$ZS_STATE/cache/as${asn}.lst"
  url="https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}&sourceapp=${ZS_NAME}"
  if (( ! CACHED_ONLY )) && (( $(file_age_hours "$cache") >= ASN_CACHE_HOURS )); then
    if fetch "$url" "$WORK/dl" && extract_json <"$WORK/dl" >"$WORK/tok" && [[ -s $WORK/tok ]]; then
      mv "$WORK/tok" "$cache"
      printf 'AS%s\n' "$asn" >"$cache.src"
      say src_ok "AS" "$(count_lines "$cache")" "AS${asn}"
    elif [[ -f $cache ]]; then
      say src_cache "AS" "$(count_lines "$cache")" "AS${asn}"
    else
      say src_fail "AS" 0 "AS${asn}"
    fi
  fi
  [[ -f $cache ]] && cat "$cache" >>"$WORK/tokens"
  return 0
}

build_lists() {
  WORK=$(mktemp -d)
  mkdir -p "$ZS_STATE/cache"
  : >"$WORK/tokens"
  (( CACHED_ONLY )) || say fetching

  local src fmt url
  for src in "${SOURCES[@]}"; do
    fmt=${src%% *}
    url=${src#* }
    pull_source "$fmt" "$url" "$url"
  done

  local a
  for a in "${ASNS[@]}"; do
    pull_asn "$a"
  done

  printf '%s\n' "${STATIC_NETS[@]+"${STATIC_NETS[@]}"}" >"$ZS_STATE/cache/static.lst"
  echo "STATIC_NETS" >"$ZS_STATE/cache/static.lst.src"
  cat "$ZS_STATE/cache/static.lst" >>"$WORK/tokens"
  [[ -f $ZS_STATE/ban.lst ]] && cat "$ZS_STATE/ban.lst" >>"$WORK/tokens"

  normalize "$WORK/v4" "$WORK/v6" <"$WORK/tokens"
  sort -u -o "$WORK/v4" "$WORK/v4"
  sort -u -o "$WORK/v6" "$WORK/v6"
  (( IPV6 )) || : >"$WORK/v6"

  local n4 n6
  n4=$(count_lines "$WORK/v4")
  n6=$(count_lines "$WORK/v6")
  if (( n4 + n6 == 0 )); then
    rm -f "$WORK/v4" "$WORK/v6"
    warn empty_lists
    return 1
  fi
  say built "$n4" "$n6"
  cp "$WORK/v4" "$ZS_STATE/block4.lst"
  cp "$WORK/v6" "$ZS_STATE/block6.lst"
  date '+%Y-%m-%d %H:%M:%S' >"$ZS_STATE/updated"
}

build_whitelist() {
  local tok="$WORK/wl_tokens"
  : >"$tok"
  printf '%s\n' "${WHITELIST[@]}" >>"$tok"
  [[ -f $ZS_STATE/allow.lst ]] && cat "$ZS_STATE/allow.lst" >>"$tok"
  if (( AUTO_WHITELIST_LOCAL )) && have ip; then
    ip -o addr show 2>/dev/null | awk '{print $4}' | sed 's#/.*##' >>"$tok" || true
  fi
  normalize_loose "$WORK/wl4" "$WORK/wl6" <"$tok"
  sort -u -o "$WORK/wl4" "$WORK/wl4"
  sort -u -o "$WORK/wl6" "$WORK/wl6"
  (( IPV6 )) || : >"$WORK/wl6"
}

nft_elements() {
  local set=$1 file=$2
  [[ -s $file ]] || return 0
  printf 'add element inet %s %s {\n' "$ZS_TABLE" "$set"
  sed '$!s/$/,/' "$file"
  printf '}\n'
}

nft_log() {
  (( LOG_DROPS )) || return 0
  printf '    %s limit rate %s log prefix "%s: " level info\n' "$1" "$LOG_RATE" "$ZS_NAME"
}

nft_render() {
  local t=$ZS_TABLE
  cat <<EOF
table inet $t {
  set block4 { type ipv4_addr; flags interval; auto-merge; }
  set block6 { type ipv6_addr; flags interval; auto-merge; }
  set allow4 { type ipv4_addr; flags interval; auto-merge; }
  set allow6 { type ipv6_addr; flags interval; auto-merge; }
  chain pre { type filter hook prerouting priority -160; policy accept; }
}
flush chain inet $t pre
flush set inet $t block4
flush set inet $t block6
flush set inet $t allow4
flush set inet $t allow6
EOF
  nft_elements block4 "$WORK/v4"
  nft_elements block6 "$WORK/v6"
  nft_elements allow4 "$WORK/wl4"
  nft_elements allow6 "$WORK/wl6"

  printf 'table inet %s {\n  chain pre {\n' "$t"
  printf '    iifname "lo" accept\n'
  printf '    ip saddr @allow4 accept\n'
  printf '    ip6 saddr @allow6 accept\n'
  if (( BAD_TCP_FLAGS )); then
    printf '    tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter name badflags drop\n'
    printf '    tcp flags & (fin|psh|urg) == fin|psh|urg counter name badflags drop\n'
    printf '    tcp flags & (syn|fin) == syn|fin counter name badflags drop\n'
    printf '    tcp flags & (syn|rst) == syn|rst counter name badflags drop\n'
    printf '    tcp flags & (fin|ack) == fin counter name badflags drop\n'
  fi
  nft_log "ct state new,invalid ip saddr @block4"
  printf '    ct state new,invalid ip saddr @block4 counter name rkn4 drop\n'
  nft_log "ct state new,invalid ip6 saddr @block6"
  printf '    ct state new,invalid ip6 saddr @block6 counter name rkn6 drop\n'
  if (( DROP_PING )); then
    printf '    icmp type echo-request counter name ping drop\n'
    printf '    icmpv6 type echo-request counter name ping drop\n'
  fi
  printf '  }\n}\n'
}

nft_counters() {
  printf 'table inet %s {\n' "$ZS_TABLE"
  local c
  for c in rkn4 rkn6 badflags ping; do
    printf '  counter %s { }\n' "$c"
  done
  printf '}\n'
}

nft_apply() {
  local f="$WORK/ruleset.nft"
  { nft_counters; nft_render; } >"$f"
  if (( DRY_RUN )); then
    say dry_run
    cat "$f"
    return 0
  fi
  if ! nft -f "$f"; then
    nft delete table inet "$ZS_TABLE" 2>/dev/null || true
    nft -f "$f"
  fi
}

nft_active() { nft list table inet "$ZS_TABLE" >/dev/null 2>&1; }

nft_stop() { nft delete table inet "$ZS_TABLE" 2>/dev/null || true; }

nft_test() {
  local ip=$1 set
  if [[ $ip == *:* ]]; then set=$2; else set=$3; fi
  nft get element inet "$ZS_TABLE" "$set" "{ $ip }" >/dev/null 2>&1
}

nft_stats() {
  local c line pk
  for c in rkn4 rkn6 badflags ping; do
    [[ $c == badflags ]] && (( ! BAD_TCP_FLAGS )) && continue
    [[ $c == ping ]] && (( ! DROP_PING )) && continue
    line=$(nft list counter inet "$ZS_TABLE" "$c" 2>/dev/null | grep -oE 'packets [0-9]+' || true)
    [[ -n $line ]] || continue
    pk=${line#packets }
    say st_dropped_by "$c" "$pk"
  done
}

ipset_load() {
  local name=$1 family=$2 file=$3 n max tmp="${1}-tmp"
  n=$(count_lines "$file")
  max=65536
  while (( max < n * 2 )); do max=$(( max * 2 )); done
  {
    printf 'create %s hash:net family %s hashsize 4096 maxelem %s -exist\n' "$name" "$family" "$max"
    printf 'create %s hash:net family %s hashsize 4096 maxelem %s -exist\n' "$tmp" "$family" "$max"
    printf 'flush %s\n' "$tmp"
    [[ -s $file ]] && sed "s/^/add ${tmp} /" "$file"
    printf 'swap %s %s\n' "$tmp" "$name"
    printf 'destroy %s\n' "$tmp"
  } >"$WORK/ipset.restore"
  if (( DRY_RUN )); then
    head -n 8 "$WORK/ipset.restore"
    return 0
  fi
  ipset destroy "$tmp" 2>/dev/null || true
  if ! ipset restore -exist <"$WORK/ipset.restore"; then
    ipset destroy "$tmp" 2>/dev/null || true
    ipset destroy "$name" 2>/dev/null || true
    ipset restore -exist <"$WORK/ipset.restore"
  fi
}

ipt_log() {
  (( LOG_DROPS )) || return 0
  local rate=${LOG_RATE/minute/min}
  rate=${rate/second/sec}
  "$1" -t mangle -A "$ZS_CHAIN" -m conntrack --ctstate NEW,INVALID -m set --match-set "$2" src \
    -m limit --limit "$rate" -j LOG --log-prefix "${ZS_NAME}: " --log-level info
}

ipt_rules() {
  local ipt=$1 fam=$2
  local sb="${ZS_SET}${fam}" sa="${ZS_SET}w${fam}"
  if (( DRY_RUN )); then
    printf '%s -t mangle -N %s; -A PREROUTING -j %s; drop NEW,INVALID from set %s, whitelist %s\n' \
      "$ipt" "$ZS_CHAIN" "$ZS_CHAIN" "$sb" "$sa"
    return 0
  fi
  "$ipt" -t mangle -N "$ZS_CHAIN" 2>/dev/null || "$ipt" -t mangle -F "$ZS_CHAIN"
  "$ipt" -t mangle -A "$ZS_CHAIN" -i lo -j RETURN
  "$ipt" -t mangle -A "$ZS_CHAIN" -m set --match-set "$sa" src -j RETURN
  if (( BAD_TCP_FLAGS )); then
    "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags ALL NONE -j DROP
    "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP
    "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags FIN,ACK FIN -j DROP
  fi
  ipt_log "$ipt" "$sb"
  "$ipt" -t mangle -A "$ZS_CHAIN" -m conntrack --ctstate NEW,INVALID -m set --match-set "$sb" src -j DROP
  if (( DROP_PING )); then
    if [[ $fam == 4 ]]; then
      "$ipt" -t mangle -A "$ZS_CHAIN" -p icmp --icmp-type echo-request -j DROP
    else
      "$ipt" -t mangle -A "$ZS_CHAIN" -p ipv6-icmp --icmpv6-type echo-request -j DROP
    fi
  fi
  "$ipt" -t mangle -C PREROUTING -j "$ZS_CHAIN" 2>/dev/null || "$ipt" -t mangle -I PREROUTING 1 -j "$ZS_CHAIN"
}

ipt_apply() {
  (( DRY_RUN )) && say dry_run
  ipset_load "${ZS_SET}4" inet "$WORK/v4"
  ipset_load "${ZS_SET}w4" inet "$WORK/wl4"
  ipt_rules iptables 4
  if (( IPV6 )) && have ip6tables; then
    ipset_load "${ZS_SET}6" inet6 "$WORK/v6"
    ipset_load "${ZS_SET}w6" inet6 "$WORK/wl6"
    ipt_rules ip6tables 6
  fi
}

ipt_stop_one() {
  local ipt=$1
  have "$ipt" || return 0
  while "$ipt" -t mangle -D PREROUTING -j "$ZS_CHAIN" 2>/dev/null; do :; done
  "$ipt" -t mangle -F "$ZS_CHAIN" 2>/dev/null || true
  "$ipt" -t mangle -X "$ZS_CHAIN" 2>/dev/null || true
}

ipt_stop() {
  ipt_stop_one iptables
  ipt_stop_one ip6tables
  local s
  for s in "${ZS_SET}4" "${ZS_SET}6" "${ZS_SET}w4" "${ZS_SET}w6"; do
    ipset destroy "$s" 2>/dev/null || true
  done
}

ipt_active() { iptables -t mangle -C PREROUTING -j "$ZS_CHAIN" 2>/dev/null; }

ipt_test() {
  local ip=$1
  if [[ $ip == *:* ]]; then ipset test "$2" "$ip" >/dev/null 2>&1
  else ipset test "$3" "$ip" >/dev/null 2>&1
  fi
}

ipt_stats() {
  local ipt pk
  for ipt in iptables ip6tables; do
    have "$ipt" || continue
    pk=$("$ipt" -t mangle -L "$ZS_CHAIN" -n -v -x 2>/dev/null | awk '$3 == "DROP" { s += $1 } END { print s + 0 }')
    say st_dropped_by "$ipt" "$pk"
  done
}

apply_rules() {
  [[ -n $WORK ]] || WORK=$(mktemp -d)
  if [[ ! -f $WORK/v4 ]]; then
    [[ -f $ZS_STATE/block4.lst || -f $ZS_STATE/block6.lst ]] || die no_cache "$ZS_NAME"
    cp "$ZS_STATE/block4.lst" "$WORK/v4" 2>/dev/null || : >"$WORK/v4"
    cp "$ZS_STATE/block6.lst" "$WORK/v6" 2>/dev/null || : >"$WORK/v6"
    (( IPV6 )) || : >"$WORK/v6"
  fi
  build_whitelist
  case "$BACKEND" in
    nft) nft_apply ;;
    iptables) ipt_apply ;;
  esac
  (( DRY_RUN )) && return 0
  local n4 n6 nw
  n4=$(count_lines "$WORK/v4")
  n6=$(count_lines "$WORK/v6")
  nw=$(( $(count_lines "$WORK/wl4") + $(count_lines "$WORK/wl6") ))
  info applied "$BACKEND" "$n4" "$n6" "$nw"
  note "applied: backend=$BACKEND v4=$n4 v6=$n6 whitelist=$nw"
}

do_update() {
  take_lock
  build_lists || true
  apply_rules
}

cmd_update() { need_root; pick_backend; do_update; }

cmd_apply() {
  need_root; pick_backend
  CACHED_ONLY=1
  do_update
}

cmd_stop() {
  need_root; pick_backend; take_lock
  case "$BACKEND" in
    nft) nft_stop ;;
    iptables) ipt_stop ;;
  esac
  info stopped "$BACKEND"
  note "stopped"
}

timer_state() {
  if have systemctl && [[ -f $ZS_UNIT_DIR/${ZS_NAME}-update.timer ]]; then
    local next
    next=$(systemctl show "${ZS_NAME}-update.timer" -p NextElapseUSecRealtime --value 2>/dev/null || true)
    printf '%s, %s' "$(systemctl is-active "${ZS_NAME}-update.timer" 2>/dev/null || true)" "${next:-?}"
  elif [[ -f $ZS_CRON ]]; then
    printf 'cron'
  else
    tr_ st_off
  fi
}

cmd_status() {
  need_root; pick_backend
  say st_title "$ZS_NAME" "$ZS_VERSION"
  say st_backend "$BACKEND"
  local on
  case "$BACKEND" in
    nft) nft_active && on=$(tr_ st_on) || on=$(tr_ st_off) ;;
    iptables) ipt_active && on=$(tr_ st_on) || on=$(tr_ st_off) ;;
  esac
  say st_active "$on"
  say st_counts "$(count_lines "$ZS_STATE/block4.lst")" "$(count_lines "$ZS_STATE/block6.lst")"
  if [[ -f $ZS_STATE/updated ]]; then
    say st_updated "$(cat "$ZS_STATE/updated")"
  else
    say st_updated "$(tr_ st_never)"
  fi
  say st_timer "$(timer_state)"
  case "$BACKEND" in
    nft) nft_stats ;;
    iptables) ipt_stats ;;
  esac
}

v4_sources() {
  local ip=$1 f
  for f in "$ZS_STATE"/cache/*.lst "$ZS_STATE/ban.lst"; do
    [[ -f $f ]] || continue
    awk -v ip="$ip" '
      function v4int(a,   o, n, i, v) {
        n = split(a, o, "."); if (n != 4) return -1
        v = 0; for (i = 1; i <= 4; i++) v = v * 256 + o[i]
        return v
      }
      BEGIN { x = v4int(ip) }
      {
        n = split($1, p, "/"); if (index(p[1], ":")) next
        b = (n == 2) ? p[2] : 32
        s = v4int(p[1]); if (s < 0) next
        blk = 2 ^ (32 - b); s = int(s / blk) * blk
        if (x >= s && x < s + blk) { print $1; exit }
      }' "$f" | while read -r net; do
        local src
        src=$(cat "$f.src" 2>/dev/null || basename "$f")
        say ck_src "$src" "$net"
      done
  done
}

cmd_check() {
  local ip=${1:-}
  [[ -n $ip ]] && is_ip "$ip" || die bad_ip "${ip:-?}"
  need_root; pick_backend
  local hit=1 wl=1
  case "$BACKEND" in
    nft)
      nft_test "$ip" allow6 allow4 && wl=0
      nft_test "$ip" block6 block4 && hit=0 ;;
    iptables)
      ipt_test "$ip" "${ZS_SET}w6" "${ZS_SET}w4" && wl=0
      ipt_test "$ip" "${ZS_SET}6" "${ZS_SET}4" && hit=0 ;;
  esac
  local found="" active=1
  case "$BACKEND" in
    nft) nft_active && active=0 ;;
    iptables) ipt_active && active=0 ;;
  esac
  [[ $ip == *:* ]] || found=$(v4_sources "$ip")
  if [[ -n $found ]] && (( active != 0 )); then
    hit=0
  fi
  if (( wl == 0 )); then
    say ck_wl "$ip"
  elif (( hit == 0 )); then
    say ck_in "$ip"
  else
    say ck_out "$ip"
  fi
  if [[ -n $found ]] && (( wl != 0 && hit == 0 )); then
    printf '%s\n' "$found"
  fi
}

list_edit() {
  local op=$1 file=$2 x=${3:-}
  [[ -n $x ]] || die bad_ip "?"
  local norm
  norm=$(norm_one "$x")
  [[ -n $norm ]] || die bad_ip "$x"
  need_root
  mkdir -p "$ZS_STATE"
  touch "$file"
  if [[ $op == add ]]; then
    grep -qxF "$norm" "$file" || printf '%s\n' "$norm" >>"$file"
    say added "$norm" "$file"
  else
    if grep -qxF "$norm" "$file"; then
      grep -vxF "$norm" "$file" >"$file.new" || true
      mv "$file.new" "$file"
      say removed "$norm" "$file"
    else
      say not_found "$norm" "$file"
    fi
  fi
  pick_backend
  CACHED_ONLY=1
  do_update
}

cmd_report() {
  local top=${1:-20}
  [[ $top =~ ^[0-9]+$ ]] || top=20
  local data
  if have journalctl; then
    data=$(journalctl -k --since "-7 days" --no-pager 2>/dev/null | grep "${ZS_NAME}: " || true)
  fi
  if [[ -z ${data:-} ]]; then
    data=$(grep -h "${ZS_NAME}: " /var/log/kern.log /var/log/messages 2>/dev/null || true)
  fi
  if [[ -z $data ]]; then
    say report_none "$ZS_CONF"
    return 0
  fi
  say report_title
  printf '%s\n' "$data" | grep -oE 'SRC=[^ ]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$top"
}

cc() { if [[ $UI_LANG == ru ]]; then printf '# %s\n' "$1"; else printf '# %s\n' "$2"; fi; }

write_config() {
  local ssh_ip=$1
  mkdir -p "$(dirname "$ZS_CONF")"
  {
    cc "Конфиг ${ZS_NAME} ${ZS_VERSION}. После правки: ${ZS_NAME} update" \
       "${ZS_NAME} ${ZS_VERSION} config. After editing: ${ZS_NAME} update"
    echo
    cc "Язык сообщений: ru или en (пусто: по локали)." \
       "Message language: ru or en (empty: from locale)."
    echo "UI_LANG=\"$UI_LANG\""
    echo
    cc "Бэкенд: auto, nft или iptables (iptables + ipset)." \
       "Backend: auto, nft or iptables (iptables + ipset)."
    echo 'BACKEND="auto"'
    echo
    cc "Фильтровать IPv6 (1) или нет (0)." \
       "Filter IPv6 (1) or not (0)."
    echo 'IPV6=1'
    echo
    cc "Писать отброшенные пакеты в журнал ядра (нужно для команды report)." \
       "Log dropped packets to the kernel log (needed for the report command)."
    echo 'LOG_DROPS=0'
    echo 'LOG_RATE="10/minute"'
    echo
    cc "Отбрасывать пакеты с невозможными TCP-флагами (NULL, XMAS, SYN+FIN): так сканируют nmap и зонды." \
       "Drop packets with impossible TCP flags (NULL, XMAS, SYN+FIN) used by nmap and probes."
    echo 'BAD_TCP_FLAGS=1'
    echo
    cc "Не отвечать на ping вообще никому (сервер не виден при ICMP-сканировании)." \
       "Do not answer ping from anyone (server is invisible to ICMP sweeps)."
    echo 'DROP_PING=0'
    echo
    cc "Автоматически пропускать адреса самого сервера." \
       "Always allow the server's own addresses."
    echo 'AUTO_WHITELIST_LOCAL=1'
    echo
    cc "Самые широкие допустимые подсети из списков: защита от ошибочных записей вроде 0.0.0.0/0." \
       "Widest networks accepted from lists: guards against bogus entries like 0.0.0.0/0."
    echo 'MIN_PREFIX4=8'
    echo 'MIN_PREFIX6=19'
    echo
    echo 'DOWNLOAD_TIMEOUT=60'
    cc "Как часто перезапрашивать подсети ASN в RIPEstat, часов." \
       "How often to re-query ASN prefixes from RIPEstat, hours."
    echo 'ASN_CACHE_HOURS=24'
    echo
    cc "Расписание обновления (systemd OnCalendar). После смены: ${ZS_NAME} install" \
       "Update schedule (systemd OnCalendar). After changing: ${ZS_NAME} install"
    echo 'UPDATE_CALENDAR="*-*-* 00/6:17:00"'
    echo
    cc "Источники: \"формат URL\". Форматы: plain (адрес в начале строки), json (поля cidr/prefix), dshield." \
       "Sources: \"format URL\". Formats: plain (address at line start), json (cidr/prefix fields), dshield."
    cc "C24Be/AS_Network_List: подсети РКН, ГРЧЦ, НКЦКИ, ФСБ, МВД и других госорганов РФ, обновляется ежедневно." \
       "C24Be/AS_Network_List: networks of RKN, GRCHC, NKCKI, FSB, MVD and other Russian agencies, updated daily."
    echo 'SOURCES=('
    local s
    for s in "${SOURCES[@]}"; do printf '  "%s"\n' "$s"; done
    echo ')'
    echo
    cc "Автономные системы, все анонсируемые ими подсети блокируются (данные RIPEstat). 61280: ФГУП ГРЧЦ." \
       "Autonomous systems whose announced networks are all blocked (RIPEstat data). 61280: FGUP GRCHC."
    echo 'ASNS=(61280)'
    echo
    cc "Отдельные подсети. 85.142.100.0/24: сканер CyberOK Skipa (по их abuse policy)." \
       "Extra networks. 85.142.100.0/24: CyberOK Skipa scanner (per their abuse policy)."
    echo 'STATIC_NETS=("85.142.100.0/24")'
    echo
    cc "Белый список: эти адреса не блокируются никогда. Команды allow/disallow ведут отдельный файл." \
       "Whitelist: never blocked. The allow/disallow commands keep a separate file."
    if [[ -n $ssh_ip ]]; then
      printf 'WHITELIST=("%s")\n' "$ssh_ip"
    else
      echo 'WHITELIST=()'
    fi
  } >"$ZS_CONF"
  chmod 600 "$ZS_CONF"
}

ssh_client_ip() {
  local ip=""
  if [[ -n ${SSH_CLIENT:-} ]]; then
    ip=${SSH_CLIENT%% *}
  elif [[ -n ${SSH_CONNECTION:-} ]]; then
    ip=${SSH_CONNECTION%% *}
  elif have who; then
    ip=$(who -m 2>/dev/null | sed -nE 's/.*\(([0-9a-fA-F:.]+)\).*/\1/p' | head -n1)
  fi
  [[ -n $ip ]] && is_ip "$ip" && printf '%s' "$ip"
  return 0
}

install_units() {
  local self=$ZS_BIN
  if have systemctl && [[ -d /run/systemd/system ]]; then
    cat >"$ZS_UNIT_DIR/${ZS_NAME}.service" <<EOF
[Unit]
Description=Zaslon: drop RKN probes and scanners
Documentation=${ZS_URL}
After=local-fs.target nftables.service netfilter-persistent.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${self} apply --cached
ExecStop=${self} stop

[Install]
WantedBy=multi-user.target
EOF
    cat >"$ZS_UNIT_DIR/${ZS_NAME}-update.service" <<EOF
[Unit]
Description=Zaslon: update RKN block lists
Documentation=${ZS_URL}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${self} update
Nice=10
EOF
    cat >"$ZS_UNIT_DIR/${ZS_NAME}-update.timer" <<EOF
[Unit]
Description=Zaslon: scheduled RKN list update

[Timer]
OnCalendar=${UPDATE_CALENDAR}
OnBootSec=10min
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${ZS_NAME}.service" >/dev/null 2>&1
    systemctl enable --now "${ZS_NAME}-update.timer" >/dev/null 2>&1
    info installed "$UPDATE_CALENDAR"
  else
    cat >"$ZS_CRON" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
@reboot root ${self} apply --cached >/dev/null 2>&1
17 */6 * * * root ${self} update >/dev/null 2>&1
EOF
    info installed_cron
  fi
}

cmd_install() {
  need_root
  local src
  src=$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")
  if [[ -f $src && $src != "$ZS_BIN" ]]; then
    install -m 0755 "$src" "$ZS_BIN"
  fi
  if [[ -f $ZS_CONF ]]; then
    say conf_kept "$ZS_CONF"
    load_config
    detect_lang
  else
    local ip
    ip=$(ssh_client_ip)
    write_config "$ip"
    say conf_created "$ZS_CONF"
    [[ -n $ip ]] && info wl_ssh "$ip"
    load_config
  fi
  pick_backend
  mkdir -p "$ZS_STATE/cache"
  do_update
  release_lock
  install_units
}

cmd_uninstall() {
  need_root
  if have systemctl; then
    systemctl disable --now "${ZS_NAME}-update.timer" >/dev/null 2>&1 || true
    systemctl disable "${ZS_NAME}.service" >/dev/null 2>&1 || true
    rm -f "$ZS_UNIT_DIR/${ZS_NAME}.service" "$ZS_UNIT_DIR/${ZS_NAME}-update.service" "$ZS_UNIT_DIR/${ZS_NAME}-update.timer"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$ZS_CRON"
  have nft && nft_stop
  have ipset && ipt_stop
  rm -f "$ZS_BIN"
  if (( PURGE )); then
    rm -rf "$ZS_STATE" "$ZS_CONF"
    rmdir "$(dirname "$ZS_CONF")" 2>/dev/null || true
    info purged
  else
    info uninstalled "$ZS_CONF, $ZS_STATE"
  fi
}

usage() { say usage "$ZS_NAME" "$ZS_BIN" "$ZS_CONF" "$ZS_URL"; }

main() {
  local args=() a
  while (( $# )); do
    a=$1
    case "$a" in
      --lang) ZASLON_LANG=${2:-}; shift ;;
      --lang=*) ZASLON_LANG=${a#*=} ;;
      --dry-run) DRY_RUN=1 ;;
      --cached) CACHED_ONLY=1 ;;
      --purge) PURGE=1 ;;
      -h|--help) args+=(help) ;;
      *) args+=("$a") ;;
    esac
    shift
  done
  set -- "${args[@]+"${args[@]}"}"

  load_config
  detect_lang

  local cmd=${1:-help}
  (( $# )) && shift
  case "$cmd" in
    install) cmd_install ;;
    update) cmd_update ;;
    apply) cmd_apply ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    check) cmd_check "${1:-}" ;;
    ban) list_edit add "$ZS_STATE/ban.lst" "${1:-}" ;;
    unban) list_edit del "$ZS_STATE/ban.lst" "${1:-}" ;;
    allow) list_edit add "$ZS_STATE/allow.lst" "${1:-}" ;;
    disallow) list_edit del "$ZS_STATE/allow.lst" "${1:-}" ;;
    report) cmd_report "${1:-20}" ;;
    uninstall) cmd_uninstall ;;
    version|--version|-V) printf '%s %s\n' "$ZS_NAME" "$ZS_VERSION" ;;
    help) usage ;;
    *) die unknown_cmd "$cmd" "$ZS_NAME" ;;
  esac
}

main "$@"
