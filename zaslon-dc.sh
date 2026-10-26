#!/usr/bin/env bash
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
  echo "bash 4.4+ required / нужен bash 4.4+" >&2
  exit 1
fi
set -Eeuo pipefail
umask 022

readonly ZS_NAME="zaslon-dc"
readonly ZS_VERSION="1.0.0"
readonly ZS_URL="https://github.com/0fells/zaslon"
readonly ZS_TABLE="zaslon_dc"
readonly ZS_CHAIN="ZASLON_DC"
readonly ZS_SET="zdc"
readonly ZS_BIN="/usr/local/sbin/${ZS_NAME}"
readonly ZS_CONF="${ZASLON_CONF:-/etc/zaslon/dc.conf}"
readonly ZS_STATE="${ZASLON_STATE:-/var/lib/zaslon/dc}"
readonly ZS_LOCK="/run/${ZS_NAME}.lock"
readonly ZS_UNIT_DIR="/etc/systemd/system"
readonly ZS_CRON="/etc/cron.d/${ZS_NAME}"

declare -A DC_ASN=(
  [digitalocean]="14061"
  [vultr]="20473"
  [linode]="63949"
  [contabo]="51167 141995 40021"
  [ovh]="16276 35540"
  [hetzner]="24940 213230 212317"
  [scaleway]="12876"
  [leaseweb]="60781 16265 28753 59253"
  [m247]="9009"
  [colocrossing]="36352"
  [frantech]="53667"
  [clouvider]="62240"
  [hostinger]="47583"
  [ionos]="8560"
  [netcup]="197540"
  [gcore]="199524"
  [datacamp]="212238"
  [aeza]="210644"
  [alibaba]="45102 37963"
  [tencent]="132203 45090"
  [huawei]="136907 55990"
  [ucloud]="135377"
  [aws]="16509 14618"
  [gcp]="396982"
  [azure]="8075"
  [oracle]="31898"
)

UI_LANG=""
BACKEND="auto"
IPV6=1
LOG_DROPS=0
LOG_RATE="10/minute"
BAD_TCP_FLAGS=1
AUTO_WHITELIST_LOCAL=1
MIN_PREFIX4=8
MIN_PREFIX6=19
DOWNLOAD_TIMEOUT=60
ASN_CACHE_HOURS=24
ASNDROP=1
ASNDROP_CACHE_HOURS=168
ASNDROP_URL="https://www.spamhaus.org/drop/asndrop.json"
UPDATE_CALENDAR="*-*-* 00/4:37:00"
SOURCES=(
  "plain https://iplists.firehol.org/files/firehol_level1.netset"
  "plain https://www.spamhaus.org/drop/drop.txt"
  "json https://www.spamhaus.org/drop/drop_v6.json"
  "plain https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  "plain https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
  "plain https://cinsscore.com/list/ci-badguys.txt"
  "plain https://lists.blocklist.de/lists/all.txt"
  "plain https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
  "plain https://iplists.firehol.org/files/greensnow.ipset"
  "dshield https://feeds.dshield.org/block.txt"
  "plain https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
)
SCANNER_ASNS=(398324 398705 398722 211298 213412 208843 211680 202425 49870 51396)
DC_BLOCK=(digitalocean vultr linode contabo alibaba tencent huawei ucloud colocrossing frantech m247 datacamp)
DC_EXTRA_ASNS=()
DC_EXEMPT_TCP=""
DC_EXEMPT_UDP=""
TRAP=1
TRAP_PORTS="23 135 139 445 1433 1521 2323 3306 3389 5432 5900 5985 6379 9200 11211 27017"
TRAP_TIMEOUT="1d"
FLOOD_RATE=0
FLOOD_BURST=200
FLOOD_TIMEOUT="1h"
STATIC_NETS=()
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
m bad_group      "Неизвестная группа ДЦ в DC_BLOCK: %s. Список: %s groups" \
                 "Unknown DC group in DC_BLOCK: %s. List: %s groups"
m bad_timeout    "Неверный срок %s: %s (пример: 30m, 12h, 1d)." \
                 "Invalid duration %s: %s (example: 30m, 12h, 1d)."
m bad_ports      "Неверный список портов %s: %s" \
                 "Invalid port list %s: %s"
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
m fetching       "Загрузка списков угроз..." \
                 "Downloading threat lists..."
m fetching_scan  "Сети сканеров (ASN)..." \
                 "Scanner networks (ASN)..."
m fetching_drop  "Spamhaus ASN-DROP: автономных систем %s (кэш %s ч)..." \
                 "Spamhaus ASN-DROP: %s autonomous systems (cache %s h)..."
m drop_progress  "  ASN-DROP: %s из %s, новых запросов %s" \
                 "  ASN-DROP: %s of %s, fresh queries %s"
m fetching_dc    "Сети дата-центров: %s" \
                 "Data center networks: %s"
m built          "Угрозы: IPv4 %s, IPv6 %s. Дата-центры: IPv4 %s, IPv6 %s." \
                 "Threats: IPv4 %s, IPv6 %s. Data centers: IPv4 %s, IPv6 %s."
m empty_lists    "Списки пусты: правила не меняю, чтобы не снять защиту по ошибке." \
                 "Lists are empty: rules left unchanged so protection is not dropped by mistake."
m no_cache       "Нет сохранённых списков. Сначала выполните: %s update" \
                 "No saved lists. Run first: %s update"
m applied        "Правила применены (%s): угрозы %s, ДЦ %s, белый список %s, ловушек %s." \
                 "Rules applied (%s): threats %s, DC %s, whitelist %s, traps %s."
m stopped        "Защита снята, правила %s удалены." \
                 "Protection disabled, %s rules removed."
m installed      "Установлено. Обновление списков по расписанию: %s" \
                 "Installed. Scheduled list updates: %s"
m installed_cron "Установлено без systemd: обновление через cron каждые 4 часа." \
                 "Installed without systemd: cron updates every 4 hours."
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
m st_counts      "Угрозы:            IPv4 %s, IPv6 %s" \
                 "Threats:           IPv4 %s, IPv6 %s"
m st_dc          "Дата-центры:       IPv4 %s, IPv6 %s (%s)" \
                 "Data centers:      IPv4 %s, IPv6 %s (%s)"
m st_trapped     "Пойманы ловушкой:  %s адресов" \
                 "Caught by traps:   %s addresses"
m st_updated     "Обновлено:         %s" \
                 "Updated:           %s"
m st_never       "никогда" \
                 "never"
m st_timer       "Таймер обновления: %s" \
                 "Update timer:      %s"
m st_dropped_by  "  %-16s %12s пакетов" \
                 "  %-16s %12s packets"
m ck_in          "%s ЕСТЬ в списке угроз." \
                 "%s IS in the threat list."
m ck_dc          "%s принадлежит заблокированному дата-центру." \
                 "%s belongs to a blocked data center."
m ck_trap        "%s пойман ловушкой (временный бан)." \
                 "%s was caught by a trap (temporary ban)."
m ck_out         "%s не блокируется." \
                 "%s is not blocked."
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
m untrapped      "%s снят с временного бана." \
                 "%s released from the temporary ban."
m report_none    "Записей о блокировках нет. Включите LOG_DROPS=1 в %s." \
                 "No drop records. Set LOG_DROPS=1 in %s."
m report_title   "Самые активные заблокированные источники:" \
                 "Most active blocked sources:"
m port_skip      "Порт %s занят службой, ловушка на нём не ставится." \
                 "Port %s is used by a service, no trap there."
m groups_title   "Группы дата-центров (* включены в DC_BLOCK):" \
                 "Data center groups (* enabled in DC_BLOCK):"

m usage "Использование: %s [--lang ru|en] [--dry-run] <команда> [аргументы]

Блокирует сканеры, ботнеты и хостинги, откуда идут атаки:
  - публичные списки угроз (FireHOL, Spamhaus DROP, Emerging Threats, CINS,
    blocklist.de, abuse.ch, GreenSnow, DShield, IPsum);
  - сети сканеров интернета (Censys, Driftnet, Onyphe, BitSight и др.);
  - Spamhaus ASN-DROP: автономные системы под контролем злоумышленников;
  - выбранные дата-центры (DigitalOcean, Vultr, Contabo, Alibaba, Tencent...);
  - порты-ловушки: кто стучится в 23, 445, 3389 и т. п., получает бан;
  - по желанию, бан за слишком частые новые соединения.
Блокируются только новые входящие соединения: ответы на ваши исходящие
запросы к этим сетям проходят.

Команды:
  install            установить в %s, создать конфиг, включить автообновление
  update             скачать списки и применить правила
  apply [--cached]   применить правила из сохранённых списков
  stop               снять правила (до следующего apply или перезагрузки)
  status             состояние, размеры списков, счётчики
  check <IP>         проверить, блокируется ли адрес и из какого он списка
  ban <IP/сеть>      добавить свой адрес или подсеть в блок-лист
  unban <IP/сеть>    убрать из своего блок-листа и из бана ловушки
  allow <IP/сеть>    добавить в белый список
  disallow <IP/сеть> убрать из белого списка
  trapped            кто сейчас в бане ловушки
  groups             группы дата-центров и их ASN
  report [N]         топ-N заблокированных источников по журналу (LOG_DROPS=1)
  uninstall [--purge] удалить (с --purge также конфиг и кэш)
  version            версия

Конфиг: %s
Проект: %s" \
"Usage: %s [--lang ru|en] [--dry-run] <command> [args]

Blocks scanners, botnets and the hosting networks attacks come from:
  - public threat feeds (FireHOL, Spamhaus DROP, Emerging Threats, CINS,
    blocklist.de, abuse.ch, GreenSnow, DShield, IPsum);
  - internet scanner networks (Censys, Driftnet, Onyphe, BitSight and more);
  - Spamhaus ASN-DROP: autonomous systems run by criminals;
  - chosen data centers (DigitalOcean, Vultr, Contabo, Alibaba, Tencent...);
  - trap ports: whoever knocks on 23, 445, 3389 and so on gets banned;
  - optionally, a ban for too many new connections.
Only new inbound connections are blocked: replies to your own outbound
requests to these networks pass.

Commands:
  install            install to %s, create config, enable auto-updates
  update             download lists and apply rules
  apply [--cached]   apply rules from saved lists
  stop               remove rules (until the next apply or reboot)
  status             state, list sizes, counters
  check <IP>         tell whether an address is blocked and by which list
  ban <IP/net>       add your own address or network to the block list
  unban <IP/net>     remove from your block list and from the trap ban
  allow <IP/net>     add to the whitelist
  disallow <IP/net>  remove from the whitelist
  trapped            who is banned by the traps now
  groups             data center groups and their ASNs
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

c_red="" c_grn="" c_yel="" c_off=""
if [[ -t 1 ]]; then
  c_red=$'\e[31m' c_grn=$'\e[32m' c_yel=$'\e[33m' c_off=$'\e[0m'
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

check_config() {
  local g p
  for g in "${DC_BLOCK[@]+"${DC_BLOCK[@]}"}"; do
    [[ -n ${DC_ASN[$g]:-} ]] || die bad_group "$g" "$ZS_NAME"
  done
  [[ $TRAP_TIMEOUT =~ ^[0-9]+[smhd]$ ]] || die bad_timeout TRAP_TIMEOUT "$TRAP_TIMEOUT"
  [[ $FLOOD_TIMEOUT =~ ^[0-9]+[smhd]$ ]] || die bad_timeout FLOOD_TIMEOUT "$FLOOD_TIMEOUT"
  for p in TRAP_PORTS DC_EXEMPT_TCP DC_EXEMPT_UDP; do
    [[ ${!p} =~ ^[0-9\ ]*$ ]] || die bad_ports "$p" "${!p}"
  done
  [[ $FLOOD_RATE =~ ^[0-9]+$ ]] || FLOOD_RATE=0
  [[ $FLOOD_BURST =~ ^[0-9]+$ ]] || FLOOD_BURST=200
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

to_seconds() {
  local v=${1%?} u=${1: -1}
  case "$u" in
    s) echo "$v" ;;
    m) echo $(( v * 60 )) ;;
    h) echo $(( v * 3600 )) ;;
    d) echo $(( v * 86400 )) ;;
  esac
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
  local fmt=$1 url=$2 dest=$3 cache tmp n
  cache="$ZS_STATE/cache/$(src_key "$url").lst"
  tmp="$WORK/dl"
  if (( CACHED_ONLY )); then
    [[ -f $cache ]] && cat "$cache" >>"$dest"
    return 0
  fi
  if fetch "$url" "$tmp"; then
    "extract_${fmt}" <"$tmp" >"$WORK/tok" || true
    if [[ -s $WORK/tok ]]; then
      mv "$WORK/tok" "$cache"
      printf '%s\n' "$url" >"$cache.src"
      say src_ok "$fmt" "$(count_lines "$cache")" "$url"
    elif [[ -f $cache ]]; then
      say src_empty "$fmt" "$(count_lines "$cache")" "$url"
    else
      say src_fail "$fmt" 0 "$url"
    fi
  elif [[ -f $cache ]]; then
    say src_cache "$fmt" "$(count_lines "$cache")" "$url"
  else
    say src_fail "$fmt" 0 "$url"
  fi
  [[ -f $cache ]] && cat "$cache" >>"$dest"
  return 0
}

ASN_FRESH=0
pull_asn() {
  local asn=$1 dest=$2 label=$3 max_age=$4 quiet=${5:-0} cache url
  asn=${asn#AS}
  asn=${asn#as}
  [[ $asn =~ ^[0-9]+$ ]] || return 0
  cache="$ZS_STATE/cache/as${asn}.lst"
  url="https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}&sourceapp=${ZS_NAME}"
  if (( ! CACHED_ONLY )) && (( $(file_age_hours "$cache") >= max_age )); then
    ASN_FRESH=$(( ASN_FRESH + 1 ))
    if fetch "$url" "$WORK/dl" && extract_json <"$WORK/dl" >"$WORK/tok" && [[ -s $WORK/tok ]]; then
      mv "$WORK/tok" "$cache"
      (( quiet )) || say src_ok "AS" "$(count_lines "$cache")" "AS${asn} ${label}"
    elif [[ -f $cache ]]; then
      touch "$cache"
      (( quiet )) || say src_cache "AS" "$(count_lines "$cache")" "AS${asn} ${label}"
    else
      : >"$cache"
      (( quiet )) || say src_fail "AS" 0 "AS${asn} ${label}"
    fi
  fi
  printf 'AS%s %s\n' "$asn" "$label" >"$cache.src"
  [[ -f $cache ]] && cat "$cache" >>"$dest"
  return 0
}

pull_asndrop() {
  local dest=$1 url=$ASNDROP_URL list="$ZS_STATE/cache/asndrop.asns"
  if (( ! CACHED_ONLY )) && fetch "$url" "$WORK/dl"; then
    grep -oE '"asn" *: *[0-9]+' "$WORK/dl" | grep -oE '[0-9]+$' | sort -un >"$WORK/asns" || true
    [[ -s $WORK/asns ]] && mv "$WORK/asns" "$list"
  fi
  [[ -s $list ]] || return 0
  local total i=0 a
  total=$(count_lines "$list")
  (( CACHED_ONLY )) || say fetching_drop "$total" "$ASNDROP_CACHE_HOURS"
  ASN_FRESH=0
  while read -r a; do
    i=$(( i + 1 ))
    pull_asn "$a" "$dest" "Spamhaus ASN-DROP" "$ASNDROP_CACHE_HOURS" 1
    if (( ! CACHED_ONLY && (i % 100 == 0 || i == total) )); then
      say drop_progress "$i" "$total" "$ASN_FRESH"
    fi
  done <"$list"
}

build_lists() {
  WORK=${WORK:-$(mktemp -d)}
  mkdir -p "$ZS_STATE/cache"
  : >"$WORK/threat"
  : >"$WORK/dc"

  (( CACHED_ONLY )) || say fetching
  local src fmt url
  for src in "${SOURCES[@]+"${SOURCES[@]}"}"; do
    fmt=${src%% *}
    url=${src#* }
    pull_source "$fmt" "$url" "$WORK/threat"
  done

  (( CACHED_ONLY )) || say fetching_scan
  local a
  for a in "${SCANNER_ASNS[@]+"${SCANNER_ASNS[@]}"}"; do
    pull_asn "$a" "$WORK/threat" "scanner" "$ASN_CACHE_HOURS"
  done

  (( ASNDROP )) && pull_asndrop "$WORK/threat"

  printf '%s\n' "${STATIC_NETS[@]+"${STATIC_NETS[@]}"}" >"$ZS_STATE/cache/static.lst"
  echo "STATIC_NETS" >"$ZS_STATE/cache/static.lst.src"
  cat "$ZS_STATE/cache/static.lst" >>"$WORK/threat"
  [[ -f $ZS_STATE/ban.lst ]] && cat "$ZS_STATE/ban.lst" >>"$WORK/threat"

  local g groups="${DC_BLOCK[*]+"${DC_BLOCK[*]}"}"
  if [[ -n $groups || ${#DC_EXTRA_ASNS[@]} -gt 0 ]]; then
    (( CACHED_ONLY )) || say fetching_dc "${groups:-—}"
    for g in "${DC_BLOCK[@]+"${DC_BLOCK[@]}"}"; do
      for a in ${DC_ASN[$g]}; do
        pull_asn "$a" "$WORK/dc" "$g" "$ASN_CACHE_HOURS"
      done
    done
    for a in "${DC_EXTRA_ASNS[@]+"${DC_EXTRA_ASNS[@]}"}"; do
      pull_asn "$a" "$WORK/dc" "DC_EXTRA_ASNS" "$ASN_CACHE_HOURS"
    done
  fi

  normalize "$WORK/v4" "$WORK/v6" <"$WORK/threat"
  normalize "$WORK/dc4" "$WORK/dc6" <"$WORK/dc"
  local f
  for f in v4 v6 dc4 dc6; do
    sort -u -o "$WORK/$f" "$WORK/$f"
  done
  if (( ! IPV6 )); then
    : >"$WORK/v6"
    : >"$WORK/dc6"
  fi

  local n4 n6 d4 d6
  n4=$(count_lines "$WORK/v4")
  n6=$(count_lines "$WORK/v6")
  d4=$(count_lines "$WORK/dc4")
  d6=$(count_lines "$WORK/dc6")
  if (( n4 + n6 == 0 )); then
    rm -f "$WORK/v4" "$WORK/v6" "$WORK/dc4" "$WORK/dc6"
    warn empty_lists
    return 1
  fi
  say built "$n4" "$n6" "$d4" "$d6"
  cp "$WORK/v4" "$ZS_STATE/block4.lst"
  cp "$WORK/v6" "$ZS_STATE/block6.lst"
  cp "$WORK/dc4" "$ZS_STATE/dc4.lst"
  cp "$WORK/dc6" "$ZS_STATE/dc6.lst"
  date '+%Y-%m-%d %H:%M:%S' >"$ZS_STATE/updated"
}

build_whitelist() {
  local tok="$WORK/wl_tokens"
  : >"$tok"
  printf '%s\n' "${WHITELIST[@]+"${WHITELIST[@]}"}" >>"$tok"
  [[ -f $ZS_STATE/allow.lst ]] && cat "$ZS_STATE/allow.lst" >>"$tok"
  if (( AUTO_WHITELIST_LOCAL )) && have ip; then
    ip -o addr show 2>/dev/null | awk '{print $4}' | sed 's#/.*##' >>"$tok" || true
  fi
  normalize_loose "$WORK/wl4" "$WORK/wl6" <"$tok"
  sort -u -o "$WORK/wl4" "$WORK/wl4"
  sort -u -o "$WORK/wl6" "$WORK/wl6"
  (( IPV6 )) || : >"$WORK/wl6"
}

listening_ports() {
  have ss || return 0
  ss -Hlntu 2>/dev/null | awk '{print $5}' |
    grep -vE '^(127\.|\[::1\]|::1)' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un
}

trap_ports() {
  (( TRAP )) || return 0
  local busy p out=""
  busy=" $(listening_ports | tr '\n' ' ') "
  for p in $TRAP_PORTS; do
    (( p >= 1 && p <= 65535 )) || continue
    if [[ $busy == *" $p "* ]]; then
      (( DRY_RUN )) || warn port_skip "$p"
      continue
    fi
    out+="$p "
  done
  printf '%s' "${out% }"
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
  printf '    %s limit rate %s log prefix "%s %s: " level info\n' "$1" "$LOG_RATE" "$ZS_NAME" "$2"
}

nft_portset() { printf '{ %s }' "$(printf '%s' "$1" | tr -s ' ' | sed 's/ /, /g')"; }

nft_render() {
  local t=$ZS_TABLE ports=$1
  cat <<EOF
table inet $t {
  counter threat { }
  counter dc { }
  counter trap { }
  counter flood { }
  counter badflags { }
  set block4 { type ipv4_addr; flags interval; auto-merge; }
  set block6 { type ipv6_addr; flags interval; auto-merge; }
  set dc4 { type ipv4_addr; flags interval; auto-merge; }
  set dc6 { type ipv6_addr; flags interval; auto-merge; }
  set allow4 { type ipv4_addr; flags interval; auto-merge; }
  set allow6 { type ipv6_addr; flags interval; auto-merge; }
  set trap4 { type ipv4_addr; flags dynamic, timeout; timeout ${TRAP_TIMEOUT}; size 262144; }
  set trap6 { type ipv6_addr; flags dynamic, timeout; timeout ${TRAP_TIMEOUT}; size 262144; }
  set rate4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; size 262144; }
  set rate6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; size 262144; }
  chain pre { type filter hook prerouting priority -155; policy accept; }
}
flush chain inet $t pre
flush set inet $t block4
flush set inet $t block6
flush set inet $t dc4
flush set inet $t dc6
flush set inet $t allow4
flush set inet $t allow6
EOF
  nft_elements block4 "$WORK/v4"
  nft_elements block6 "$WORK/v6"
  nft_elements dc4 "$WORK/dc4"
  nft_elements dc6 "$WORK/dc6"
  nft_elements allow4 "$WORK/wl4"
  nft_elements allow6 "$WORK/wl6"

  local new="ct state new,invalid"
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

  nft_log "$new ip saddr @block4" threat
  printf '    %s ip saddr @block4 counter name threat drop\n' "$new"
  nft_log "$new ip6 saddr @block6" threat
  printf '    %s ip6 saddr @block6 counter name threat drop\n' "$new"

  printf '    %s ip saddr @trap4 counter name trap drop\n' "$new"
  printf '    %s ip6 saddr @trap6 counter name trap drop\n' "$new"
  if [[ -n $ports ]]; then
    nft_log "ct state new tcp dport $(nft_portset "$ports")" trap
    printf '    meta nfproto ipv4 ct state new tcp dport %s add @trap4 { ip saddr } counter name trap drop\n' "$(nft_portset "$ports")"
    printf '    meta nfproto ipv6 ct state new tcp dport %s add @trap6 { ip6 saddr } counter name trap drop\n' "$(nft_portset "$ports")"
  fi

  if (( FLOOD_RATE > 0 )); then
    printf '    meta nfproto ipv4 ct state new update @rate4 { ip saddr limit rate over %s/second burst %s packets } add @trap4 { ip saddr timeout %s } counter name flood drop\n' \
      "$FLOOD_RATE" "$FLOOD_BURST" "$FLOOD_TIMEOUT"
    printf '    meta nfproto ipv6 ct state new update @rate6 { ip6 saddr limit rate over %s/second burst %s packets } add @trap6 { ip6 saddr timeout %s } counter name flood drop\n' \
      "$FLOOD_RATE" "$FLOOD_BURST" "$FLOOD_TIMEOUT"
  fi

  if [[ -n $DC_EXEMPT_TCP ]]; then
    printf '    tcp dport %s accept\n' "$(nft_portset "$DC_EXEMPT_TCP")"
  fi
  if [[ -n $DC_EXEMPT_UDP ]]; then
    printf '    udp dport %s accept\n' "$(nft_portset "$DC_EXEMPT_UDP")"
  fi
  nft_log "$new ip saddr @dc4" dc
  printf '    %s ip saddr @dc4 counter name dc drop\n' "$new"
  nft_log "$new ip6 saddr @dc6" dc
  printf '    %s ip6 saddr @dc6 counter name dc drop\n' "$new"
  printf '  }\n}\n'
}

nft_apply() {
  local f="$WORK/ruleset.nft"
  nft_render "$1" >"$f"
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
  if [[ $ip == *:* ]]; then set="${2}6"; else set="${2}4"; fi
  nft get element inet "$ZS_TABLE" "$set" "{ $ip }" >/dev/null 2>&1
}

nft_trapped() {
  local s
  for s in trap4 trap6; do
    nft list set inet "$ZS_TABLE" "$s" 2>/dev/null |
      grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}( timeout [0-9a-z]+)?( expires [0-9a-z]+)?|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}( timeout [0-9a-z]+)?( expires [0-9a-z]+)?' || true
  done
}

nft_untrap() {
  local ip=$1 s
  if [[ $ip == *:* ]]; then s=trap6; else s=trap4; fi
  nft delete element inet "$ZS_TABLE" "$s" "{ $ip }" 2>/dev/null
}

nft_stats() {
  local c line pk
  for c in threat trap flood dc badflags; do
    [[ $c == trap ]] && (( ! TRAP )) && continue
    [[ $c == flood ]] && (( FLOOD_RATE == 0 )) && continue
    [[ $c == badflags ]] && (( ! BAD_TCP_FLAGS )) && continue
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
    head -n 4 "$WORK/ipset.restore"
    return 0
  fi
  ipset destroy "$tmp" 2>/dev/null || true
  if ! ipset restore -exist <"$WORK/ipset.restore"; then
    ipset destroy "$tmp" 2>/dev/null || true
    ipset destroy "$name" 2>/dev/null || true
    ipset restore -exist <"$WORK/ipset.restore"
  fi
}

ipset_dynamic() {
  local name=$1 family=$2 secs
  secs=$(to_seconds "$TRAP_TIMEOUT")
  (( DRY_RUN )) && { printf 'create %s hash:ip family %s timeout %s\n' "$name" "$family" "$secs"; return 0; }
  ipset create "$name" hash:ip family "$family" timeout "$secs" maxelem 262144 -exist
}

ipt_rate() {
  local rate=${LOG_RATE/minute/min}
  printf '%s' "${rate/second/sec}"
}

IPT() {
  if (( DRY_RUN )); then
    printf '%s\n' "$*"
  else
    "$@"
  fi
}

ipt_chain() {
  local ipt=$1 ch=$2
  (( DRY_RUN )) && { printf '%s -t mangle -N %s\n' "$ipt" "$ch"; return 0; }
  "$ipt" -t mangle -N "$ch" 2>/dev/null || "$ipt" -t mangle -F "$ch"
}

ipt_log() {
  local ipt=$1 tag=$2
  shift 2
  (( LOG_DROPS )) || return 0
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" "$@" -m limit --limit "$(ipt_rate)" \
    -j LOG --log-prefix "${ZS_NAME} ${tag}: " --log-level info
}

ipt_rules() {
  local ipt=$1 fam=$2 ports=$3
  local sb="${ZS_SET}${fam}" sd="${ZS_SET}d${fam}" sa="${ZS_SET}w${fam}" st="${ZS_SET}t${fam}"
  local ban="${ZS_CHAIN}_BAN" fban="${ZS_CHAIN}_FL"
  local new=(-m conntrack --ctstate NEW,INVALID)

  ipt_chain "$ipt" "$ban"
  IPT "$ipt" -t mangle -A "$ban" -j SET --add-set "$st" src --exist
  IPT "$ipt" -t mangle -A "$ban" -j DROP

  ipt_chain "$ipt" "$fban"
  IPT "$ipt" -t mangle -A "$fban" -j SET --add-set "$st" src --exist --timeout "$(to_seconds "$FLOOD_TIMEOUT")"
  IPT "$ipt" -t mangle -A "$fban" -j DROP

  ipt_chain "$ipt" "$ZS_CHAIN"
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" -i lo -j RETURN
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" -m set --match-set "$sa" src -j RETURN
  if (( BAD_TCP_FLAGS )); then
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags ALL NONE -j DROP
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp --tcp-flags FIN,ACK FIN -j DROP
  fi

  ipt_log "$ipt" threat "${new[@]}" -m set --match-set "$sb" src
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" "${new[@]}" -m set --match-set "$sb" src -j DROP
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" "${new[@]}" -m set --match-set "$st" src -j DROP

  if [[ -n $ports ]]; then
    local chunk=() p
    for p in $ports; do
      chunk+=("$p")
      if (( ${#chunk[@]} == 15 )); then
        IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp -m multiport --dports "$(IFS=,; echo "${chunk[*]}")" \
          -m conntrack --ctstate NEW -j "$ban"
        chunk=()
      fi
    done
    if (( ${#chunk[@]} )); then
      IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp -m multiport --dports "$(IFS=,; echo "${chunk[*]}")" \
        -m conntrack --ctstate NEW -j "$ban"
    fi
  fi

  if (( FLOOD_RATE > 0 )); then
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -m conntrack --ctstate NEW -m hashlimit \
      --hashlimit-above "${FLOOD_RATE}/sec" --hashlimit-burst "$FLOOD_BURST" \
      --hashlimit-mode srcip --hashlimit-name "${ZS_SET}fl${fam}" -j "$fban"
  fi

  if [[ -n $DC_EXEMPT_TCP ]]; then
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p tcp -m multiport --dports "$(echo "$DC_EXEMPT_TCP" | tr -s ' ' ',')" -j RETURN
  fi
  if [[ -n $DC_EXEMPT_UDP ]]; then
    IPT "$ipt" -t mangle -A "$ZS_CHAIN" -p udp -m multiport --dports "$(echo "$DC_EXEMPT_UDP" | tr -s ' ' ',')" -j RETURN
  fi
  ipt_log "$ipt" dc "${new[@]}" -m set --match-set "$sd" src
  IPT "$ipt" -t mangle -A "$ZS_CHAIN" "${new[@]}" -m set --match-set "$sd" src -j DROP

  if (( DRY_RUN )); then
    printf '%s -t mangle -I PREROUTING 1 -j %s\n' "$ipt" "$ZS_CHAIN"
  else
    "$ipt" -t mangle -C PREROUTING -j "$ZS_CHAIN" 2>/dev/null || "$ipt" -t mangle -I PREROUTING 1 -j "$ZS_CHAIN"
  fi
}

ipt_apply() {
  local ports=$1
  (( DRY_RUN )) && say dry_run
  ipset_load "${ZS_SET}4" inet "$WORK/v4"
  ipset_load "${ZS_SET}d4" inet "$WORK/dc4"
  ipset_load "${ZS_SET}w4" inet "$WORK/wl4"
  ipset_dynamic "${ZS_SET}t4" inet
  ipt_rules iptables 4 "$ports"
  if (( IPV6 )) && { have ip6tables || (( DRY_RUN )); }; then
    ipset_load "${ZS_SET}6" inet6 "$WORK/v6"
    ipset_load "${ZS_SET}d6" inet6 "$WORK/dc6"
    ipset_load "${ZS_SET}w6" inet6 "$WORK/wl6"
    ipset_dynamic "${ZS_SET}t6" inet6
    ipt_rules ip6tables 6 "$ports"
  fi
}

ipt_stop_one() {
  local ipt=$1 ch
  have "$ipt" || return 0
  while "$ipt" -t mangle -D PREROUTING -j "$ZS_CHAIN" 2>/dev/null; do :; done
  for ch in "$ZS_CHAIN" "${ZS_CHAIN}_BAN" "${ZS_CHAIN}_FL"; do
    "$ipt" -t mangle -F "$ch" 2>/dev/null || true
  done
  for ch in "$ZS_CHAIN" "${ZS_CHAIN}_BAN" "${ZS_CHAIN}_FL"; do
    "$ipt" -t mangle -X "$ch" 2>/dev/null || true
  done
}

ipt_stop() {
  ipt_stop_one iptables
  ipt_stop_one ip6tables
  local s f
  for f in 4 6; do
    for s in "${ZS_SET}${f}" "${ZS_SET}d${f}" "${ZS_SET}w${f}" "${ZS_SET}t${f}"; do
      ipset destroy "$s" 2>/dev/null || true
    done
  done
}

ipt_active() { iptables -t mangle -C PREROUTING -j "$ZS_CHAIN" 2>/dev/null; }

ipt_test() {
  local ip=$1 set
  if [[ $ip == *:* ]]; then set="${ZS_SET}${2}6"; else set="${ZS_SET}${2}4"; fi
  ipset test "$set" "$ip" >/dev/null 2>&1
}

ipt_trapped() {
  local f
  for f in 4 6; do
    ipset list "${ZS_SET}t${f}" 2>/dev/null | sed -n '/^Members:/,$p' | sed '1d' || true
  done
}

ipt_untrap() {
  local ip=$1 f=4
  [[ $ip == *:* ]] && f=6
  ipset del "${ZS_SET}t${f}" "$ip" 2>/dev/null
}

ipt_stats() {
  local ipt pk
  for ipt in iptables ip6tables; do
    have "$ipt" || continue
    pk=$("$ipt" -t mangle -L "$ZS_CHAIN" -n -v -x 2>/dev/null | awk '$3 == "DROP" { s += $1 } END { print s + 0 }')
    say st_dropped_by "$ipt" "$pk"
  done
}

load_saved() {
  local f
  for f in v4:block4 v6:block6 dc4:dc4 dc6:dc6; do
    cp "$ZS_STATE/${f#*:}.lst" "$WORK/${f%%:*}" 2>/dev/null || : >"$WORK/${f%%:*}"
  done
  if (( ! IPV6 )); then
    : >"$WORK/v6"
    : >"$WORK/dc6"
  fi
}

apply_rules() {
  [[ -n $WORK ]] || WORK=$(mktemp -d)
  if [[ ! -f $WORK/v4 ]]; then
    [[ -f $ZS_STATE/block4.lst || -f $ZS_STATE/block6.lst ]] || die no_cache "$ZS_NAME"
    load_saved
  fi
  build_whitelist
  local ports
  ports=$(trap_ports)
  case "$BACKEND" in
    nft) nft_apply "$ports" ;;
    iptables) ipt_apply "$ports" ;;
  esac
  (( DRY_RUN )) && return 0
  local nb nd nw nt
  nb=$(( $(count_lines "$WORK/v4") + $(count_lines "$WORK/v6") ))
  nd=$(( $(count_lines "$WORK/dc4") + $(count_lines "$WORK/dc6") ))
  nw=$(( $(count_lines "$WORK/wl4") + $(count_lines "$WORK/wl6") ))
  nt=$(wc -w <<<"$ports" | tr -d ' ')
  info applied "$BACKEND" "$nb" "$nd" "$nw" "$nt"
  note "applied: backend=$BACKEND threats=$nb dc=$nd whitelist=$nw traps=$nt"
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

trapped_list() {
  case "$BACKEND" in
    nft) nft_trapped ;;
    iptables) ipt_trapped ;;
  esac
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
  say st_dc "$(count_lines "$ZS_STATE/dc4.lst")" "$(count_lines "$ZS_STATE/dc6.lst")" \
    "${DC_BLOCK[*]+"${DC_BLOCK[*]}"}"
  say st_trapped "$(trapped_list | grep -c . || true)"
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
    [[ -s $f ]] || continue
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
  is_ip "$ip" || die bad_ip "${ip:-?}"
  need_root; pick_backend
  local wl=1 hit=1 dc=1 tr=1
  case "$BACKEND" in
    nft)
      nft_test "$ip" allow && wl=0
      nft_test "$ip" block && hit=0
      nft_test "$ip" dc && dc=0
      nft_test "$ip" trap && tr=0 ;;
    iptables)
      ipt_test "$ip" w && wl=0
      ipt_test "$ip" "" && hit=0
      ipt_test "$ip" d && dc=0
      ipt_test "$ip" t && tr=0 ;;
  esac
  local found="" g active=1
  case "$BACKEND" in
    nft) nft_active && active=0 ;;
    iptables) ipt_active && active=0 ;;
  esac
  [[ $ip == *:* ]] || found=$(v4_sources "$ip")
  if [[ -n $found ]] && (( active != 0 && hit && dc )); then
    hit=0
    for g in "${DC_BLOCK[@]+"${DC_BLOCK[@]}"}" DC_EXTRA_ASNS; do
      if grep -q " $g (" <<<"$found"; then
        dc=0
        grep -qv " $g (" <<<"$found" || hit=1
      fi
    done
  fi
  if (( wl == 0 )); then
    say ck_wl "$ip"
  else
    (( hit == 0 )) && say ck_in "$ip"
    (( dc == 0 )) && say ck_dc "$ip"
    (( tr == 0 )) && say ck_trap "$ip"
    (( hit && dc && tr )) && say ck_out "$ip"
  fi
  if [[ -n $found ]] && (( wl != 0 && (hit == 0 || dc == 0) )); then
    printf '%s\n' "$found"
  fi
}

cmd_trapped() {
  need_root; pick_backend
  trapped_list
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
  if [[ $op == del && $file == */ban.lst && $x != */* ]]; then
    local ok=1
    case "$BACKEND" in
      nft) nft_untrap "$x" && ok=0 ;;
      iptables) ipt_untrap "$x" && ok=0 ;;
    esac
    (( ok == 0 )) && say untrapped "$x"
  fi
  CACHED_ONLY=1
  do_update
}

cmd_groups() {
  say groups_title
  local g mark on=" ${DC_BLOCK[*]+"${DC_BLOCK[*]}"} "
  for g in $(printf '%s\n' "${!DC_ASN[@]}" | sort); do
    mark=" "
    [[ $on == *" $g "* ]] && mark="*"
    printf '  %s %-14s AS%s\n' "$mark" "$g" "$(printf '%s' "${DC_ASN[$g]}" | sed 's/ /, AS/g')"
  done
}

cmd_report() {
  local top=${1:-20}
  [[ $top =~ ^[0-9]+$ ]] || top=20
  local data=""
  if have journalctl; then
    data=$(journalctl -k --since "-7 days" --no-pager 2>/dev/null | grep "${ZS_NAME} " || true)
  fi
  if [[ -z $data ]]; then
    data=$(grep -h "${ZS_NAME} " /var/log/kern.log /var/log/messages 2>/dev/null || true)
  fi
  if [[ -z $data ]]; then
    say report_none "$ZS_CONF"
    return 0
  fi
  say report_title
  printf '%s\n' "$data" |
    sed -nE "s/.*${ZS_NAME} ([a-z]+): .*SRC=([^ ]+).*/\\2 \\1/p" |
    sort | uniq -c | sort -rn | head -n "$top"
}

cc() { if [[ $UI_LANG == ru ]]; then printf '# %s\n' "$1"; else printf '# %s\n' "$2"; fi; }

print_array() {
  local name=$1
  shift
  if (( $# == 0 )); then
    printf '%s=()\n' "$name"
    return
  fi
  printf '%s=(\n' "$name"
  local s
  for s in "$@"; do printf '  "%s"\n' "$s"; done
  printf ')\n'
}

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
    cc "Отбрасывать пакеты с невозможными TCP-флагами (NULL, XMAS, SYN+FIN)." \
       "Drop packets with impossible TCP flags (NULL, XMAS, SYN+FIN)."
    echo 'BAD_TCP_FLAGS=1'
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
    echo 'UPDATE_CALENDAR="*-*-* 00/4:37:00"'
    echo
    cc "Списки угроз: \"формат URL\". Форматы: plain (адрес в начале строки), json (поля cidr/prefix), dshield." \
       "Threat feeds: \"format URL\". Formats: plain (address at line start), json (cidr/prefix fields), dshield."
    print_array SOURCES "${SOURCES[@]}"
    echo
    cc "Сети сканеров интернета: Censys (398324, 398705, 398722), Driftnet (211298), Onyphe (213412)," \
       "Internet scanner networks: Censys (398324, 398705, 398722), Driftnet (211298), Onyphe (213412),"
    cc "Alpha Strike Labs (208843), BitSight (211680), IP Volume (202425), Alsycon (49870), Pfcloud (51396)." \
       "Alpha Strike Labs (208843), BitSight (211680), IP Volume (202425), Alsycon (49870), Pfcloud (51396)."
    echo "SCANNER_ASNS=(${SCANNER_ASNS[*]})"
    echo
    cc "Spamhaus ASN-DROP: около 450 автономных систем под контролем спамеров и ботнетов." \
       "Spamhaus ASN-DROP: about 450 autonomous systems run by spammers and botnets."
    cc "Первый запуск делает по запросу в RIPEstat на каждую, дальше кэш на ASNDROP_CACHE_HOURS часов." \
       "The first run queries RIPEstat once per ASN, then caches for ASNDROP_CACHE_HOURS hours."
    echo 'ASNDROP=1'
    echo 'ASNDROP_CACHE_HOURS=168'
    echo
    cc "Блокируемые дата-центры. Все группы: ${ZS_NAME} groups" \
       "Blocked data centers. All groups: ${ZS_NAME} groups"
    cc "Осторожно с aws, gcp, azure, oracle, hetzner, ovh: там живут вебхуки, мониторинг и чужие VPN-ноды." \
       "Careful with aws, gcp, azure, oracle, hetzner, ovh: webhooks, monitoring and other VPN nodes live there."
    echo "DC_BLOCK=(${DC_BLOCK[*]})"
    cc "Дополнительные ASN дата-центров." \
       "Extra data center ASNs."
    echo 'DC_EXTRA_ASNS=()'
    cc "Порты, на которые дата-центрам можно (например \"80 443\" для сайта). Списки угроз действуют всё равно." \
       "Ports data centers may still reach (e.g. \"80 443\" for a website). Threat lists still apply."
    echo 'DC_EXEMPT_TCP=""'
    echo 'DC_EXEMPT_UDP=""'
    echo
    cc "Порты-ловушки: кто открывает на них TCP-соединение, получает бан на TRAP_TIMEOUT." \
       "Trap ports: whoever opens a TCP connection to them is banned for TRAP_TIMEOUT."
    cc "Порты, на которых реально работает служба, пропускаются автоматически." \
       "Ports a real service listens on are skipped automatically."
    echo 'TRAP=1'
    echo "TRAP_PORTS=\"$TRAP_PORTS\""
    echo 'TRAP_TIMEOUT="1d"'
    echo
    cc "Бан за флуд: больше FLOOD_RATE новых соединений в секунду с одного адреса (0: выключено)." \
       "Flood ban: more than FLOOD_RATE new connections per second from one address (0: off)."
    cc "Не включайте на прокси, если клиенты сидят за общим NAT мобильных операторов." \
       "Do not enable on a proxy whose clients share carrier-grade NAT addresses."
    echo 'FLOOD_RATE=0'
    echo 'FLOOD_BURST=200'
    echo 'FLOOD_TIMEOUT="1h"'
    echo
    cc "Свои подсети для блокировки. Команды ban/unban ведут отдельный файл." \
       "Your own networks to block. The ban/unban commands keep a separate file."
    echo 'STATIC_NETS=()'
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
Description=Zaslon: block scanners, botnets and data center networks
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
Description=Zaslon: update threat and data center lists
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
Description=Zaslon: scheduled threat list update

[Timer]
OnCalendar=${UPDATE_CALENDAR}
OnBootSec=15min
RandomizedDelaySec=20min
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
37 */4 * * * root ${self} update >/dev/null 2>&1
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
  else
    local ip
    ip=$(ssh_client_ip)
    write_config "$ip"
    say conf_created "$ZS_CONF"
    [[ -n $ip ]] && info wl_ssh "$ip"
  fi
  load_config
  detect_lang
  check_config
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
    install|uninstall|help|version|--version|-V|groups) ;;
    *) check_config ;;
  esac
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
    trapped) cmd_trapped ;;
    groups) cmd_groups ;;
    report) cmd_report "${1:-20}" ;;
    uninstall) cmd_uninstall ;;
    version|--version|-V) printf '%s %s\n' "$ZS_NAME" "$ZS_VERSION" ;;
    help) usage ;;
    *) die unknown_cmd "$cmd" "$ZS_NAME" ;;
  esac
}

main "$@"
