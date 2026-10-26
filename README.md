<h1 align="center">Zaslon</h1>

<p align="center">
  <b>Заслон для сервера: прячет его от зондов РКН, сканеров и ботнетов.</b><br>
  <b>A barrier for your server: hides it from RKN probes, scanners and botnets.</b>
</p>

<p align="center">
  <a href="#русский">Русский</a> | <a href="#english">English</a>
</p>

# Русский

Два самостоятельных bash-скрипта для Linux-серверов (VPN, прокси, VPS):

| Скрипт | Что делает |
|---|---|
| `zaslon-rkn.sh` | Защищает сервер от зондов и сканеров РКН: ГРЧЦ, НКЦКИ, CyberOK (Skipa), подсетей госорганов РФ |
| `zaslon-dc.sh` | Блокирует сканеры и ботнеты: списки угроз, сети сканеров, Spamhaus ASN-DROP, крупные дата-центры, порты-ловушки |

Оба скрипта отбрасывают **только новые входящие соединения** с адресов из списков. Сервер для таких адресов выглядит выключенным: нет ни ответа, ни RST. Исходящие соединения и ответы на них проходят, так что сайты и сервисы из этих сетей через ваш прокси открываются.

Скрипты можно ставить вместе: у каждого своя таблица nftables (или своя цепочка iptables), свой конфиг и своё расписание обновлений.

## Возможности

- **nftables или iptables + ipset**, выбор автоматический. Правила в собственной таблице `inet zaslon_rkn` / `inet zaslon_dc` с хуком `prerouting`: работают до ufw и firewalld и защищают порты контейнеров Docker.
- **IPv4 и IPv6.**
- **Атомарное обновление**: списки подменяются за одну транзакцию, без мгновения без защиты.
- **Надёжность**: если источник не скачался, берётся его прошлая копия; если все списки оказались пустыми, правила не трогаются.
- **Защита от ошибок в списках**: записи вроде `0.0.0.0/0`, частные и служебные сети (10/8, 192.168/16, 100.64/10 и т. д.) отбрасываются, адреса нормализуются.
- **Защита от потери доступа**: при установке IP вашей SSH-сессии попадает в белый список, адреса самого сервера пропускаются всегда.
- **Автообновление** через systemd-таймер (или cron, если systemd нет). После перезагрузки правила восстанавливаются из кэша без сети.
- **Команды для работы**: `status`, `check <IP>` (заблокирован ли адрес и каким списком), `ban`, `unban`, `allow`, `disallow`, `report` (топ атакующих по журналу).
- **Русский и английский интерфейс**: по локали, через `--lang ru|en` или `UI_LANG` в конфиге.

### zaslon-rkn

- Подсети РКН, ГРЧЦ, НКЦКИ, ФСБ, МВД и других госорганов из [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) (обновляется ежедневно).
- Все сети AS61280 (ФГУП ГРЧЦ) по данным RIPEstat.
- Сеть сканера CyberOK Skipa `85.142.100.0/24` (из их abuse policy).
- Отбрасывание пакетов с невозможными TCP-флагами (NULL, XMAS, SYN+FIN и т. п.), которыми пользуются nmap и зонды.
- По желанию: сервер перестаёт отвечать на ping (`DROP_PING=1`).

### zaslon-dc

- Списки угроз: FireHOL level1, Spamhaus DROP (IPv4 и IPv6), Emerging Threats, CINS Army, blocklist.de, abuse.ch Feodo, GreenSnow, DShield, IPsum (адреса, попавшие минимум в 3 списка).
- Сети сканеров интернета: Censys, Driftnet, Onyphe, Alpha Strike Labs, BitSight и хостинги, откуда сканируют массово (IP Volume, Alsycon, Pfcloud).
- Spamhaus ASN-DROP: около 450 автономных систем под контролем спамеров и ботнетов.
- Дата-центры группами: по умолчанию DigitalOcean, Vultr, Linode, Contabo, Alibaba, Tencent, Huawei Cloud, UCloud, ColoCrossing, FranTech, M247, Datacamp. Можно включить AWS, Google Cloud, Azure, Oracle, Hetzner, OVH и другие (`zaslon-dc groups`). Для нужных портов дата-центрам можно оставить доступ (`DC_EXEMPT_TCP="80 443"`).
- Порты-ловушки: кто открывает соединение на 23, 445, 3389, 6379 и другие неиспользуемые порты, получает бан на сутки. Порты, где реально работает служба, пропускаются автоматически.
- По желанию: бан за флуд новыми соединениями (`FLOOD_RATE`).

## Требования

- Linux с ядром 4.x или новее, bash 4.4+, root.
- `nftables` (рекомендуется) или `iptables` + `ipset`.
- `curl` или `wget`, `awk`, `sed`, `grep`.
- Рассчитано на Debian 11+, Ubuntu 20.04+ и другие дистрибутивы с systemd или cron.

Debian/Ubuntu: `apt install nftables curl`

## Установка

```sh
curl -fsSLO https://raw.githubusercontent.com/0fells/zaslon/main/zaslon-rkn.sh
sudo bash zaslon-rkn.sh install

curl -fsSLO https://raw.githubusercontent.com/0fells/zaslon/main/zaslon-dc.sh
sudo bash zaslon-dc.sh install
```

`install` копирует скрипт в `/usr/local/sbin`, создаёт конфиг в `/etc/zaslon/`, скачивает списки, применяет правила и включает таймер обновления. Повторный `install` обновляет скрипт и не трогает конфиг.

Посмотреть правила, не применяя их:

```sh
sudo bash zaslon-dc.sh --dry-run update
```

Первый запуск `zaslon-dc` занимает несколько минут: он запрашивает в RIPEstat сети около 450 автономных систем из ASN-DROP. Дальше они кэшируются на неделю.

## Команды

Одинаковы для обоих скриптов (`zaslon-rkn` или `zaslon-dc`):

| Команда | Действие |
|---|---|
| `install` | установить, создать конфиг, включить автообновление |
| `update` | скачать списки и применить правила |
| `apply` | применить правила из сохранённых списков, без сети |
| `stop` | снять правила до следующего `apply` или перезагрузки |
| `status` | включена ли защита, размеры списков, счётчики отброшенных пакетов |
| `check <IP>` | заблокирован ли адрес и в каком списке он найден |
| `ban <IP/сеть>` / `unban <IP/сеть>` | свой блок-лист |
| `allow <IP/сеть>` / `disallow <IP/сеть>` | белый список |
| `report [N]` | топ-N заблокированных источников по журналу ядра (нужен `LOG_DROPS=1`) |
| `uninstall [--purge]` | удалить; с `--purge` также конфиг и кэш |

Только в `zaslon-dc`: `trapped` (кто сейчас забанен ловушкой), `groups` (группы дата-центров и их ASN). `unban` в `zaslon-dc` также снимает бан ловушки.

Общие ключи: `--lang ru|en`, `--dry-run`.

```sh
sudo zaslon-rkn status
sudo zaslon-dc check 167.94.138.5
sudo zaslon-dc allow 203.0.113.10
```

## Настройка

Конфиги: `/etc/zaslon/rkn.conf` и `/etc/zaslon/dc.conf`. Каждый параметр в них описан. После правки выполните `update`.

| Параметр | По умолчанию | Смысл |
|---|---|---|
| `BACKEND` | `auto` | `nft`, `iptables` или автовыбор |
| `IPV6` | `1` | фильтровать IPv6 |
| `LOG_DROPS` | `0` | писать отброшенные пакеты в журнал (для `report`) |
| `BAD_TCP_FLAGS` | `1` | отбрасывать пакеты с невозможными TCP-флагами |
| `WHITELIST` | IP вашей SSH-сессии | адреса, которые не блокируются никогда |
| `SOURCES` | см. выше | списки: `"формат URL"`, форматы `plain`, `json`, `dshield` |
| `UPDATE_CALENDAR` | каждые 6 ч (rkn), 4 ч (dc) | расписание systemd; после смены выполните `install` |
| `ASNS` (rkn) | `61280` | автономные системы, которые блокируются целиком |
| `DROP_PING` (rkn) | `0` | не отвечать на ping |
| `DC_BLOCK` (dc) | 12 групп | блокируемые дата-центры |
| `DC_EXEMPT_TCP` (dc) | пусто | порты, на которые дата-центрам можно |
| `TRAP_PORTS`, `TRAP_TIMEOUT` (dc) | 16 портов, `1d` | порты-ловушки и срок бана |
| `FLOOD_RATE` (dc) | `0` (выкл.) | бан за превышение N новых соединений в секунду |
| `ASNDROP` (dc) | `1` | использовать Spamhaus ASN-DROP |

## Как это работает

```
входящий пакет
  └─ prerouting (приоритет -160 / -155, после conntrack)
       ├─ lo, белый список ............................. пропустить
       ├─ невозможные TCP-флаги ........................ отбросить
       ├─ новое соединение из блок-листа ............... отбросить
       ├─ (dc) уже пойман ловушкой ..................... отбросить
       ├─ (dc) стук в порт-ловушку ..................... бан + отбросить
       ├─ (dc) флуд новыми соединениями ................ бан + отбросить
       ├─ (dc) новое соединение из дата-центра ......... отбросить
       └─ всё остальное ................................ дальше, к вашему файрволу
```

Блокируются состояния conntrack `new` и `invalid`. Пакеты уже установленных соединений (`established`, `related`) проходят, поэтому исходящий трафик в заблокированные сети работает.

## Ограничения

- ТСПУ стоит в сети провайдера и может подменять адрес источника. Списки отсекают массовые сканирования подрядчиков РКН, но не любой активный зонд. Защиту самого протокола (маскировка VLESS Reality, XTLS и т. п.) настраивайте в прокси.
- Блокировка AWS, Google Cloud, Azure и подобных отрежет входящие вебхуки, внешний мониторинг и прокси-цепочки через эти облака. Добавляйте нужные адреса в белый список.
- Не включайте `FLOOD_RATE` на прокси, если клиенты сидят за общим NAT мобильных операторов.
- `systemctl restart nftables` с `flush ruleset` в конфиге стирает и таблицы Zaslon. После этого выполните `apply` (или перезапустите `zaslon-rkn.service` / `zaslon-dc.service`).
- В режиме iptables `firewall-cmd --reload` сбрасывает цепочки; то же решение.

## Источники данных

Списки скачиваются напрямую у их владельцев и подчиняются их условиям: [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List), [RIPEstat](https://stat.ripe.net/), [FireHOL](https://iplists.firehol.org/), [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [Emerging Threats](https://rules.emergingthreats.net/), [CINS Army](https://cinsscore.com/), [blocklist.de](https://www.blocklist.de/), [abuse.ch](https://feodotracker.abuse.ch/), [GreenSnow](https://greensnow.co/), [DShield](https://feeds.dshield.org/), [IPsum](https://github.com/stamparm/ipsum).

## Лицензия

[MIT](LICENSE)

# English

Two standalone bash scripts for Linux servers (VPN, proxy, VPS):

| Script | What it does |
|---|---|
| `zaslon-rkn.sh` | Protects the server from probes and scanners of Roskomnadzor (RKN): GRCHC, NKCKI, CyberOK (Skipa), Russian government networks |
| `zaslon-dc.sh` | Blocks scanners and botnets: threat feeds, scanner networks, Spamhaus ASN-DROP, large data centers, trap ports |

Both scripts drop **only new inbound connections** from listed addresses. To those addresses the server looks switched off: no reply, no RST. Outbound connections and their replies pass, so sites and services in those networks still open through your proxy.

The scripts can run side by side: each has its own nftables table (or iptables chain), its own config and its own update schedule.

## Features

- **nftables or iptables + ipset**, chosen automatically. Rules live in their own `inet zaslon_rkn` / `inet zaslon_dc` table on the `prerouting` hook: they run before ufw and firewalld and also protect Docker container ports.
- **IPv4 and IPv6.**
- **Atomic updates**: lists are swapped in one transaction, with no unprotected moment.
- **Resilience**: a source that fails to download falls back to its last copy; if every list comes back empty, the rules are left untouched.
- **Guards against bad list entries**: entries like `0.0.0.0/0`, private and special ranges (10/8, 192.168/16, 100.64/10 and so on) are discarded, addresses are normalized.
- **Lockout protection**: on install the IP of your SSH session is whitelisted, and the server's own addresses are always allowed.
- **Auto-updates** via a systemd timer (or cron without systemd). After a reboot the rules are restored from cache without network access.
- **Day-to-day commands**: `status`, `check <IP>` (is an address blocked and by which list), `ban`, `unban`, `allow`, `disallow`, `report` (top attackers from the log).
- **Russian and English interface**: from the locale, via `--lang ru|en` or `UI_LANG` in the config.

### zaslon-rkn

- Networks of RKN, GRCHC, NKCKI, FSB, MVD and other Russian agencies from [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) (updated daily).
- All networks of AS61280 (FGUP GRCHC) from RIPEstat.
- The CyberOK Skipa scanner network `85.142.100.0/24` (from their abuse policy).
- Drops packets with impossible TCP flags (NULL, XMAS, SYN+FIN and so on) used by nmap and probes.
- Optionally the server stops answering ping (`DROP_PING=1`).

### zaslon-dc

- Threat feeds: FireHOL level1, Spamhaus DROP (IPv4 and IPv6), Emerging Threats, CINS Army, blocklist.de, abuse.ch Feodo, GreenSnow, DShield, IPsum (addresses seen on at least 3 lists).
- Internet scanner networks: Censys, Driftnet, Onyphe, Alpha Strike Labs, BitSight and hosting networks known for mass scanning (IP Volume, Alsycon, Pfcloud).
- Spamhaus ASN-DROP: about 450 autonomous systems run by spammers and botnets.
- Data centers by group: DigitalOcean, Vultr, Linode, Contabo, Alibaba, Tencent, Huawei Cloud, UCloud, ColoCrossing, FranTech, M247, Datacamp by default. AWS, Google Cloud, Azure, Oracle, Hetzner, OVH and others can be enabled (`zaslon-dc groups`). Data centers can keep access to chosen ports (`DC_EXEMPT_TCP="80 443"`).
- Trap ports: whoever opens a connection to 23, 445, 3389, 6379 and other unused ports is banned for a day. Ports a real service listens on are skipped automatically.
- Optionally a ban for flooding with new connections (`FLOOD_RATE`).

## Requirements

- Linux with kernel 4.x or newer, bash 4.4+, root.
- `nftables` (recommended) or `iptables` + `ipset`.
- `curl` or `wget`, `awk`, `sed`, `grep`.
- Built for Debian 11+, Ubuntu 20.04+ and other distributions with systemd or cron.

Debian/Ubuntu: `apt install nftables curl`

## Installation

```sh
curl -fsSLO https://raw.githubusercontent.com/0fells/zaslon/main/zaslon-rkn.sh
sudo bash zaslon-rkn.sh install

curl -fsSLO https://raw.githubusercontent.com/0fells/zaslon/main/zaslon-dc.sh
sudo bash zaslon-dc.sh install
```

`install` copies the script to `/usr/local/sbin`, creates a config in `/etc/zaslon/`, downloads the lists, applies the rules and enables the update timer. Running `install` again updates the script and keeps the config.

To see the rules without applying them:

```sh
sudo bash zaslon-dc.sh --dry-run update
```

The first `zaslon-dc` run takes a few minutes: it asks RIPEstat for the networks of about 450 ASN-DROP autonomous systems. After that they are cached for a week.

## Commands

The same for both scripts (`zaslon-rkn` or `zaslon-dc`):

| Command | Action |
|---|---|
| `install` | install, create config, enable auto-updates |
| `update` | download lists and apply rules |
| `apply` | apply rules from saved lists, no network needed |
| `stop` | remove rules until the next `apply` or reboot |
| `status` | whether protection is on, list sizes, dropped packet counters |
| `check <IP>` | whether an address is blocked and which list has it |
| `ban <IP/net>` / `unban <IP/net>` | your own block list |
| `allow <IP/net>` / `disallow <IP/net>` | whitelist |
| `report [N]` | top N blocked sources from the kernel log (needs `LOG_DROPS=1`) |
| `uninstall [--purge]` | remove; with `--purge` also config and cache |

`zaslon-dc` only: `trapped` (who is banned by the traps now), `groups` (data center groups and their ASNs). In `zaslon-dc`, `unban` also lifts a trap ban.

Common flags: `--lang ru|en`, `--dry-run`.

```sh
sudo zaslon-rkn status
sudo zaslon-dc check 167.94.138.5
sudo zaslon-dc allow 203.0.113.10
```

## Configuration

Configs: `/etc/zaslon/rkn.conf` and `/etc/zaslon/dc.conf`. Every option is documented inside. Run `update` after editing.

| Option | Default | Meaning |
|---|---|---|
| `BACKEND` | `auto` | `nft`, `iptables` or automatic |
| `IPV6` | `1` | filter IPv6 |
| `LOG_DROPS` | `0` | log dropped packets (for `report`) |
| `BAD_TCP_FLAGS` | `1` | drop packets with impossible TCP flags |
| `WHITELIST` | your SSH session IP | addresses that are never blocked |
| `SOURCES` | see above | lists: `"format URL"`, formats `plain`, `json`, `dshield` |
| `UPDATE_CALENDAR` | every 6 h (rkn), 4 h (dc) | systemd schedule; run `install` after changing |
| `ASNS` (rkn) | `61280` | autonomous systems blocked entirely |
| `DROP_PING` (rkn) | `0` | do not answer ping |
| `DC_BLOCK` (dc) | 12 groups | blocked data centers |
| `DC_EXEMPT_TCP` (dc) | empty | ports data centers may still reach |
| `TRAP_PORTS`, `TRAP_TIMEOUT` (dc) | 16 ports, `1d` | trap ports and ban length |
| `FLOOD_RATE` (dc) | `0` (off) | ban above N new connections per second |
| `ASNDROP` (dc) | `1` | use Spamhaus ASN-DROP |

## How it works

```
inbound packet
  └─ prerouting (priority -160 / -155, after conntrack)
       ├─ lo, whitelist ................................ accept
       ├─ impossible TCP flags ......................... drop
       ├─ new connection from the block list ........... drop
       ├─ (dc) already caught by a trap ................ drop
       ├─ (dc) knock on a trap port .................... ban + drop
       ├─ (dc) new connection flood .................... ban + drop
       ├─ (dc) new connection from a data center ....... drop
       └─ everything else .............................. on to your firewall
```

The conntrack states `new` and `invalid` are blocked. Packets of established connections (`established`, `related`) pass, so outbound traffic to blocked networks works.

## Limitations

- The TSPU sits inside the provider's network and can spoof source addresses. The lists cut off mass scans by RKN contractors, not every active probe. Protect the protocol itself (VLESS Reality, XTLS camouflage and so on) in your proxy settings.
- Blocking AWS, Google Cloud, Azure and the like cuts off inbound webhooks, external monitoring and proxy chains through those clouds. Whitelist the addresses you need.
- Do not enable `FLOOD_RATE` on a proxy whose clients share carrier-grade NAT addresses.
- `systemctl restart nftables` with `flush ruleset` in its config also wipes the Zaslon tables. Run `apply` afterwards (or restart `zaslon-rkn.service` / `zaslon-dc.service`).
- In iptables mode `firewall-cmd --reload` resets the chains; same fix.

## Data sources

Lists are downloaded directly from their owners and are subject to their terms: [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List), [RIPEstat](https://stat.ripe.net/), [FireHOL](https://iplists.firehol.org/), [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [Emerging Threats](https://rules.emergingthreats.net/), [CINS Army](https://cinsscore.com/), [blocklist.de](https://www.blocklist.de/), [abuse.ch](https://feodotracker.abuse.ch/), [GreenSnow](https://greensnow.co/), [DShield](https://feeds.dshield.org/), [IPsum](https://github.com/stamparm/ipsum).

## License

[MIT](LICENSE)
