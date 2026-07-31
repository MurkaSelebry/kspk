#!/usr/bin/env bash
#
# check_resource.sh — диагностика доступности ресурса по HTTP/HTTPS.
#
# Проверяет: DNS, ICMP, TCP-порты, маршрут, HTTP/HTTPS-ответы с таймингами,
# цепочку редиректов, TLS-сертификат и заголовки безопасности.
#
# Код возврата: 0 — все критичные проверки пройдены, 1 — есть провалы.

set -uo pipefail

# Фиксируем локаль: в ru_RU.UTF-8 ping/date выдают русский текст,
# который ломает разбор вывода. Влияет только на дочерние процессы скрипта.
export LC_ALL=C
export LANG=C

VERSION="1.3"

# ---------- Значения по умолчанию ----------
TIMEOUT=10
DO_TRACE=1
DO_PING=1
INSECURE=0
QUIET=0
VERBOSE=0
CERT_WARN_DAYS=30
EXTRA_HEADERS=()
LOGFILE=""
TARGET=""
FORCE_PORT=""

PASS=0; WARN=0; FAIL=0; SKIP=0

# ---------- Цвета ----------
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
    C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_DIM=""; C_BLD=""; C_RST=""
fi

# ---------- Вывод ----------
out()  { [[ $QUIET -eq 1 ]] && return 0; printf '%s\n' "$*"; [[ -n "$LOGFILE" ]] && printf '%s\n' "$*" | sed 's/\x1b\[[0-9;]*m//g' >>"$LOGFILE"; return 0; }
raw()  { [[ -n "$LOGFILE" ]] && printf '%s\n' "$*" | sed 's/\x1b\[[0-9;]*m//g' >>"$LOGFILE"; [[ $QUIET -eq 1 ]] && return 0; printf '%s\n' "$*"; return 0; }
sect() { out ""; out "${C_BLD}${C_BLU}═══ $* ═══${C_RST}"; }
ok()   { PASS=$((PASS+1)); out "  ${C_GRN}[ OK ]${C_RST}   $*"; }
warn() { WARN=$((WARN+1)); out "  ${C_YLW}[WARN]${C_RST}   $*"; }
fail() { FAIL=$((FAIL+1)); out "  ${C_RED}[FAIL]${C_RST}   $*"; }
skip() { SKIP=$((SKIP+1)); out "  ${C_DIM}[SKIP]${C_RST}   $*"; }
info() { out "  ${C_DIM}·${C_RST}      $*"; }
dbg()  { [[ $VERBOSE -eq 1 ]] && out "  ${C_DIM}debug: $*${C_RST}"; return 0; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
check_resource.sh v$VERSION — проверка доступности ресурса по HTTP/HTTPS

Использование:
  $(basename "$0") [опции] <URL | host>

Опции:
  -p, --port PORT       проверить дополнительный TCP-порт
  -t, --timeout SEC     таймаут сетевых операций (по умолчанию $TIMEOUT)
  -H, --header 'K: V'   дополнительный HTTP-заголовок (можно повторять)
  -d, --days N          порог предупреждения по сроку сертификата (по умолчанию $CERT_WARN_DAYS)
  -k, --insecure        не проверять валидность TLS-сертификата в curl
  -n, --no-trace        не выполнять traceroute
  -P, --no-ping         не выполнять ping
  -o, --log FILE        дублировать вывод в файл (без цветов)
  -q, --quiet           только код возврата
  -v, --verbose         подробный вывод
  -h, --help            эта справка

Примеры:
  $(basename "$0") https://example.com/api/health
  $(basename "$0") -p 8443 -t 5 example.com
  $(basename "$0") -H 'Authorization: Bearer XXX' https://api.internal/status

Код возврата: 0 — критичных ошибок нет, 1 — есть провалы, 2 — ошибка запуска.
EOF
}

# ---------- Разбор аргументов ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)    FORCE_PORT="${2:-}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:-}"; shift 2 ;;
        -H|--header)  EXTRA_HEADERS+=("-H" "${2:-}"); shift 2 ;;
        -d|--days)    CERT_WARN_DAYS="${2:-}"; shift 2 ;;
        -k|--insecure) INSECURE=1; shift ;;
        -n|--no-trace) DO_TRACE=0; shift ;;
        -P|--no-ping)  DO_PING=0; shift ;;
        -o|--log)     LOGFILE="${2:-}"; shift 2 ;;
        -q|--quiet)   QUIET=1; shift ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           echo "Неизвестная опция: $1" >&2; usage >&2; exit 2 ;;
        *)            TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]] && { usage >&2; exit 2; }
have curl || { echo "Ошибка: curl не установлен." >&2; exit 2; }
[[ -n "$LOGFILE" ]] && : >"$LOGFILE"

# ---------- Разбор URL ----------
SCHEME=""; HOST=""; PORT=""; PATH_PART="/"

if [[ "$TARGET" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$ ]]; then
    SCHEME=$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
    rest="${BASH_REMATCH[2]}"
else
    rest="$TARGET"
fi

# отбрасываем user:pass@
rest="${rest##*@}"

hostport="${rest%%/*}"
if [[ "$rest" == */* ]]; then
    PATH_PART="/${rest#*/}"
fi

if [[ "$hostport" =~ ^\[(.+)\](:([0-9]+))?$ ]]; then          # IPv6 в скобках
    HOST="${BASH_REMATCH[1]}"; PORT="${BASH_REMATCH[3]}"
elif [[ "$hostport" =~ ^([^:]+):([0-9]+)$ ]]; then
    HOST="${BASH_REMATCH[1]}"; PORT="${BASH_REMATCH[2]}"
else
    HOST="$hostport"
fi

[[ -z "$HOST" ]] && { echo "Ошибка: не удалось определить хост из '$TARGET'." >&2; exit 2; }

# Какие схемы проверяем
if [[ -n "$SCHEME" ]]; then
    SCHEMES=("$SCHEME")
else
    SCHEMES=("https" "http")
fi

CURL_BASE=(curl --silent --show-error --location
           --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT"
           --user-agent "check_resource/$VERSION")
[[ $INSECURE -eq 1 ]] && CURL_BASE+=(--insecure)
[[ ${#EXTRA_HEADERS[@]} -gt 0 ]] && CURL_BASE+=("${EXTRA_HEADERS[@]}")

out "${C_BLD}Диагностика ресурса${C_RST}"
info "цель:   $TARGET"
info "хост:   $HOST   путь: $PATH_PART"
info "старт:  $(date '+%Y-%m-%d %H:%M:%S %Z')"

# ============================================================
sect "0. Окружение"
# ============================================================
declare -a MISSING_PKGS=()
check_tool() {
    local bin="$1" pkg="$2" crit="$3"
    if have "$bin"; then
        [[ $VERBOSE -eq 1 ]] && info "$bin: $(command -v "$bin")"
        return 0
    fi
    MISSING_PKGS+=("$pkg")
    if [[ "$crit" == "crit" ]]; then
        fail "$bin не найден (пакет $pkg)"
    else
        info "$bin не найден — соответствующая проверка будет пропущена (пакет $pkg)"
    fi
}
check_tool curl       curl             crit
check_tool openssl    openssl          opt
check_tool dig        dnsutils         opt
check_tool nc         netcat-openbsd   opt
check_tool ping       iputils-ping     opt
check_tool traceroute traceroute       opt
check_tool mtr        mtr-tiny         opt

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    warn "не хватает утилит; установить: sudo apt install ${MISSING_PKGS[*]}"
else
    ok "все используемые утилиты присутствуют"
fi
info "bash ${BASH_VERSION%%(*}, $(uname -sr)"

# ============================================================
sect "1. DNS"
# ============================================================
IP4=""; IP6=""
if have dig; then
    IP4=$(dig +short +time=3 +tries=1 A "$HOST" 2>/dev/null | grep -E '^[0-9.]+$' | paste -sd' ' -)
    IP6=$(dig +short +time=3 +tries=1 AAAA "$HOST" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' | paste -sd' ' -)
elif have host; then
    IP4=$(host -t A "$HOST" 2>/dev/null | awk '/has address/{print $NF}' | paste -sd' ' -)
    IP6=$(host -t AAAA "$HOST" 2>/dev/null | awk '/has IPv6 address/{print $NF}' | paste -sd' ' -)
elif have getent; then
    IP4=$(getent ahostsv4 "$HOST" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd' ' -)
    IP6=$(getent ahostsv6 "$HOST" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd' ' -)
fi

if [[ "$HOST" =~ ^[0-9.]+$ || "$HOST" =~ : ]]; then
    skip "цель задана IP-адресом, резолвинг не требуется"
    IP4="$HOST"
elif [[ -n "$IP4" || -n "$IP6" ]]; then
    ok "имя резолвится"
    [[ -n "$IP4" ]] && info "A:    $IP4"
    [[ -n "$IP6" ]] && info "AAAA: $IP6"
    if have dig && [[ $VERBOSE -eq 1 ]]; then
        cname=$(dig +short CNAME "$HOST" 2>/dev/null | paste -sd' ' -)
        [[ -n "$cname" ]] && info "CNAME: $cname"
    fi
else
    fail "имя $HOST не резолвится — дальнейшие проверки почти наверняка провалятся"
fi

# ============================================================
sect "2. ICMP (ping)"
# ============================================================
if [[ $DO_PING -eq 0 ]]; then
    skip "отключено ключом --no-ping"
elif ! have ping; then
    skip "утилита ping недоступна"
else
    ping_out=$(ping -c 4 -W 2 "$HOST" 2>&1) || ping_out=$(ping -c 4 -t 2 "$HOST" 2>&1)
    if grep -qE '[0-9]+ (packets )?received|bytes from' <<<"$ping_out"; then
        loss=$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' <<<"$ping_out" | head -1)
        rtt=$(grep -oE '= [0-9.]+/[0-9.]+/[0-9.]+' <<<"$ping_out" | head -1 | awk -F'/' '{print $2}')
        if [[ "$loss" == 0%* || "$loss" == "0% packet loss" ]]; then
            ok "хост отвечает на ICMP (avg RTT ${rtt:-n/a} ms)"
        else
            warn "потери пакетов: ${loss:-неизвестно} (avg RTT ${rtt:-n/a} ms)"
        fi
    else
        warn "ICMP не проходит — многие хосты блокируют ping, это не всегда проблема"
        dbg "$ping_out"
    fi
fi

# ============================================================
sect "3. TCP-порты"
# ============================================================
check_port() {
    local h="$1" p="$2" label="$3"
    if have nc; then
        if nc -z -w "$TIMEOUT" "$h" "$p" >/dev/null 2>&1; then
            ok "порт $p/tcp открыт ($label)"; return 0
        fi
    elif have timeout; then
        if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
            ok "порт $p/tcp открыт ($label)"; return 0
        fi
    else
        if (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null; then
            ok "порт $p/tcp открыт ($label)"; return 0
        fi
    fi
    fail "порт $p/tcp недоступен ($label)"
    return 1
}

declare -a PORTS_TO_CHECK=()
if [[ -n "$PORT" ]]; then
    PORTS_TO_CHECK+=("$PORT:явно указан в URL")
else
    for s in "${SCHEMES[@]}"; do
        [[ "$s" == "http"  ]] && PORTS_TO_CHECK+=("80:http")
        [[ "$s" == "https" ]] && PORTS_TO_CHECK+=("443:https")
    done
fi
[[ -n "$FORCE_PORT" ]] && PORTS_TO_CHECK+=("$FORCE_PORT:дополнительный")

for entry in "${PORTS_TO_CHECK[@]}"; do
    check_port "$HOST" "${entry%%:*}" "${entry#*:}"
done

# ============================================================
sect "4. Маршрут"
# ============================================================
if [[ $DO_TRACE -eq 0 ]]; then
    skip "отключено ключом --no-trace"
elif have mtr; then
    info "mtr --report (10 циклов):"
    raw "$(mtr --report --report-cycles 10 --no-dns "$HOST" 2>&1 | sed 's/^/         /')"
    ok "трассировка выполнена (mtr)"
elif have traceroute; then
    info "traceroute (макс. 20 хопов):"
    raw "$(traceroute -w 2 -q 1 -m 20 "$HOST" 2>&1 | sed 's/^/         /')"
    ok "трассировка выполнена (traceroute)"
elif have tracepath; then
    info "tracepath:"
    raw "$(tracepath -m 20 "$HOST" 2>&1 | sed 's/^/         /')"
    ok "трассировка выполнена (tracepath)"
else
    skip "ни mtr, ни traceroute, ни tracepath не установлены"
fi

# ============================================================
sect "5. HTTP/HTTPS-запросы"
# ============================================================
probe_url() {
    local url="$1"
    local fmt='%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{size_download}|%{num_redirects}|%{url_effective}|%{http_version}|%{remote_ip}'
    local resp
    resp=$("${CURL_BASE[@]}" -o /dev/null -w "$fmt" "$url" 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        fail "$url — curl завершился с ошибкой ($rc)"
        info "${resp//$'\n'/ }"
        case $rc in
            6)  info "подсказка: не удалось разрешить имя" ;;
            7)  info "подсказка: соединение отвергнуто или порт закрыт" ;;
            28) info "подсказка: таймаут ${TIMEOUT}s — сервер отвечает слишком медленно" ;;
            35) info "подсказка: ошибка TLS-рукопожатия" ;;
            60) info "подсказка: сертификат не проходит проверку (см. ключ -k)" ;;
        esac
        return 1
    fi

    IFS='|' read -r code t_dns t_conn t_ssl t_first t_total size redirs eff_url httpver rip <<<"$resp"

    local verdict="ok"
    case "$code" in
        2*)  ok  "$url → HTTP $code" ;;
        3*)  warn "$url → HTTP $code (редирект не был разрешён)"; verdict="warn" ;;
        401|403) warn "$url → HTTP $code (доступ ограничен, но сервис отвечает)"; verdict="warn" ;;
        4*)  warn "$url → HTTP $code (ошибка клиента)"; verdict="warn" ;;
        5*)  fail "$url → HTTP $code (ошибка сервера)"; verdict="fail" ;;
        000) fail "$url → ответ не получен"; return 1 ;;
        *)   warn "$url → HTTP $code"; verdict="warn" ;;
    esac

    info "IP: ${rip}   HTTP/${httpver}   размер: ${size} B   редиректов: ${redirs}"
    [[ "$eff_url" != "$url" ]] && info "итоговый URL: $eff_url"
    printf -v timings "DNS %.0f ms | TCP %.0f ms | TLS %.0f ms | TTFB %.0f ms | всего %.0f ms" \
        "$(awk "BEGIN{print $t_dns*1000}")" \
        "$(awk "BEGIN{print ($t_conn-$t_dns)*1000}")" \
        "$(awk "BEGIN{print ($t_ssl>0)?($t_ssl-$t_conn)*1000:0}")" \
        "$(awk "BEGIN{print $t_first*1000}")" \
        "$(awk "BEGIN{print $t_total*1000}")"
    info "$timings"

    if awk "BEGIN{exit !($t_total > 3)}"; then
        warn "медленный ответ: $(awk "BEGIN{printf \"%.2f\", $t_total}") s"
    fi

    [[ "$verdict" == "fail" ]] && return 1
    return 0
}

for s in "${SCHEMES[@]}"; do
    url="${s}://${HOST}"
    [[ -n "$PORT" ]] && url="${s}://${HOST}:${PORT}"
    url="${url}${PATH_PART}"
    probe_url "$url"
done

# ---------- Цепочка редиректов ----------
if [[ " ${SCHEMES[*]} " == *" http "* ]]; then
    out ""
    info "цепочка редиректов для http://${HOST}${PATH_PART}:"
    chain=$(curl -sSI -L --max-time "$TIMEOUT" "http://${HOST}${PATH_PART}" 2>/dev/null \
            | grep -iE '^(HTTP/|location:)' | sed 's/\r$//' | sed 's/^/         /')
    if [[ -n "$chain" ]]; then
        raw "$chain"
        if grep -qi 'location: *https://' <<<"$chain"; then
            ok "HTTP редиректит на HTTPS"
        else
            warn "редиректа с HTTP на HTTPS нет"
        fi
    else
        info "заголовки получить не удалось"
    fi
fi

# ============================================================
sect "6. TLS-сертификат"
# ============================================================
tls_port="${PORT:-443}"
if [[ " ${SCHEMES[*]} " != *" https "* ]]; then
    skip "HTTPS не проверяется для данной цели"
elif ! have openssl; then
    skip "openssl не установлен"
else
    cert=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${HOST}:${tls_port}" \
           -servername "$HOST" 2>/dev/null)
    if [[ -z "$cert" ]] || ! grep -q 'BEGIN CERTIFICATE' <<<"$cert"; then
        fail "не удалось получить сертификат с ${HOST}:${tls_port}"
    else
        subject=$(openssl x509 -noout -subject <<<"$cert" 2>/dev/null | sed 's/^subject= *//')
        issuer=$(openssl x509 -noout -issuer <<<"$cert" 2>/dev/null | sed 's/^issuer= *//')
        notafter=$(openssl x509 -noout -enddate <<<"$cert" 2>/dev/null | cut -d= -f2)
        sans=$(openssl x509 -noout -ext subjectAltName <<<"$cert" 2>/dev/null | tail -n +2 | tr -d ' ' | head -c 300)
        proto=$(grep -m1 'Protocol *:' <<<"$cert" | awk -F': *' '{print $2}')
        cipher=$(grep -m1 'Cipher *:' <<<"$cert" | awk -F': *' '{print $2}')

        info "subject: ${subject:-n/a}"
        info "issuer:  ${issuer:-n/a}"
        [[ -n "$proto"  ]] && info "протокол: $proto, шифр: ${cipher:-n/a}"
        [[ -n "$sans"   ]] && info "SAN: $sans"

        # срок действия
        end_ts=$(date -d "$notafter" +%s 2>/dev/null \
                 || date -j -f "%b %e %T %Y %Z" "$notafter" +%s 2>/dev/null)
        if [[ -n "${end_ts:-}" ]]; then
            days=$(( (end_ts - $(date +%s)) / 86400 ))
            if   (( days < 0 ));  then fail "сертификат истёк $((-days)) дн. назад ($notafter)"
            elif (( days <= CERT_WARN_DAYS )); then warn "сертификат истекает через $days дн. ($notafter)"
            else ok "сертификат действителен ещё $days дн. (до $notafter)"
            fi
        else
            info "срок действия: $notafter"
        fi

        # проверка имени и цепочки
        if openssl x509 -noout -checkhost "$HOST" <<<"$cert" >/dev/null 2>&1; then
            ok "имя хоста совпадает с сертификатом"
        else
            warn "имя $HOST не найдено в CN/SAN сертификата"
        fi

        if grep -q 'Verify return code: 0 (ok)' <<<"$cert"; then
            ok "цепочка доверия проверена"
        else
            vr=$(grep -m1 'Verify return code:' <<<"$cert" | sed 's/^ *//')
            fail "проблема с цепочкой доверия: ${vr:-неизвестно}"
        fi

        # поддерживаемые версии TLS
        for v in tls1:"TLS 1.0" tls1_1:"TLS 1.1" tls1_2:"TLS 1.2" tls1_3:"TLS 1.3"; do
            flag="${v%%:*}"; name="${v#*:}"
            if echo | timeout 5 openssl s_client -"$flag" -connect "${HOST}:${tls_port}" \
                 -servername "$HOST" >/dev/null 2>&1; then
                case "$flag" in
                    tls1|tls1_1) warn "поддерживается устаревший $name — рекомендуется отключить" ;;
                    *)           info "поддерживается $name" ;;
                esac
            fi
        done
    fi
fi

# ============================================================
sect "7. Заголовки ответа"
# ============================================================
hdr_scheme="${SCHEMES[0]}"
hdr_url="${hdr_scheme}://${HOST}"
[[ -n "$PORT" ]] && hdr_url="${hdr_scheme}://${HOST}:${PORT}"
hdr_url="${hdr_url}${PATH_PART}"

headers=$("${CURL_BASE[@]}" -I "$hdr_url" 2>/dev/null | sed 's/\r$//')
if [[ -z "$headers" ]]; then
    headers=$("${CURL_BASE[@]}" -s -D - -o /dev/null "$hdr_url" 2>/dev/null | sed 's/\r$//')
fi

if [[ -z "$headers" ]]; then
    warn "заголовки получить не удалось"
else
    [[ $VERBOSE -eq 1 ]] && raw "$(sed 's/^/         /' <<<"$headers")"
    server=$(grep -i '^server:' <<<"$headers" | tail -1 | cut -d' ' -f2-)
    [[ -n "$server" ]] && info "Server: $server"

    if [[ "$hdr_scheme" == "https" ]]; then
        if grep -qi '^strict-transport-security:' <<<"$headers"; then
            ok "HSTS включён"
        else
            warn "заголовок Strict-Transport-Security отсутствует"
        fi
    fi
    for h in "content-type" "cache-control"; do
        val=$(grep -i "^${h}:" <<<"$headers" | tail -1 | cut -d' ' -f2-)
        [[ -n "$val" ]] && info "${h}: $val"
    done
fi

# ============================================================
sect "Итог"
# ============================================================
out "  ${C_GRN}пройдено: $PASS${C_RST}   ${C_YLW}предупреждений: $WARN${C_RST}   ${C_RED}провалов: $FAIL${C_RST}   ${C_DIM}пропущено: $SKIP${C_RST}"
out "  завершено: $(date '+%Y-%m-%d %H:%M:%S %Z')"
[[ -n "$LOGFILE" ]] && out "  лог: $LOGFILE"
out ""

if (( FAIL > 0 )); then
    out "  ${C_RED}${C_BLD}РЕСУРС НЕДОСТУПЕН ИЛИ РАБОТАЕТ С ОШИБКАМИ${C_RST}"
    exit 1
elif (( WARN > 0 )); then
    out "  ${C_YLW}${C_BLD}РЕСУРС ДОСТУПЕН, ЕСТЬ ЗАМЕЧАНИЯ${C_RST}"
    exit 0
else
    out "  ${C_GRN}${C_BLD}РЕСУРС ДОСТУПЕН${C_RST}"
    exit 0
fi
