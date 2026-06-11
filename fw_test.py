#!/usr/bin/env python3
"""
fw_test.py — тестирование сетевых возможностей файрвола (fw).

Скрипт прогоняет большой набор сайтов (RU-сегмент и иностранный сегмент)
и набор сетевых операций, чтобы понять, ЧТО именно пропускает или режет
файрвол: DNS, отдельные порты, TLS-хендшейк, исходящие POST, скачивание и т.д.

Принципы:
  * Только стандартная библиотека Python 3 (>=3.8).
  * Запуск БЕЗ прав root: только обычные TCP-соединения и DNS-резолв.
    Никаких raw-сокетов, ICMP-ping, iptables, изменений системы.
  * Скрипт ничего не пишет в систему, кроме отчётов в --output-dir.
  * "Вежливое" поведение к целевым сайтам: ограниченный параллелизм,
    таймауты на всё, лёгкие запросы (HEAD / Range), пауза между задачами.

Источники доменов:
  * Если рядом со скриптом (или в --domains-dir) есть domains_ru.txt и/или
    domains_foreign.txt — домены берутся оттуда (по одному в строке,
    строки с # игнорируются). Это путь к полному прогону >1000 / >5000.
  * Иначе используется встроенный сид-список реальных популярных доменов.

Автор: сгенерировано для тестирования собственного сервера.
"""

import argparse
import csv
import http.client
import json
import logging
import os
import socket
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Константы и классификация результатов
# --------------------------------------------------------------------------- #

USER_AGENT = "fw-test/1.0 (connectivity probe; +local server fw test)"

# Категории статуса одной проверки. По ним делается вывод о характере блокировки.
OK = "OK"                                  # получили валидный ответ/соединение
DNS_BLOCKED = "DNS_BLOCKED"                 # имя не резолвится (или DNS режется)
CONNECTION_REFUSED = "CONNECTION_REFUSED"   # порт закрыт / RST на SYN
CONNECTION_RESET = "CONNECTION_RESET"       # соединение сброшено
TIMEOUT = "TIMEOUT"                         # таймаут (часто молчаливый DROP в fw)
TLS_ERROR = "TLS_ERROR"                     # ошибка TLS-хендшейка/сертификата
HTTP_ERROR = "HTTP_ERROR"                   # дошли до HTTP, но код >= 400
NET_UNREACHABLE = "NET_UNREACHABLE"         # сеть/хост недостижимы
OTHER = "OTHER"                             # прочие ошибки

ALL_CATEGORIES = [
    OK, DNS_BLOCKED, CONNECTION_REFUSED, CONNECTION_RESET,
    TIMEOUT, TLS_ERROR, HTTP_ERROR, NET_UNREACHABLE, OTHER,
]

# Публичные эндпоинты для тестов скачивания и отдачи.
# Cloudflare speed-эндпоинт позволяет задать точный размер ответа в байтах.
DOWNLOAD_ENDPOINTS = [
    ("small_100kb", "https://speed.cloudflare.com/__down?bytes=100000"),
    ("medium_10mb", "https://speed.cloudflare.com/__down?bytes=10000000"),
]
# Резервные ссылки на тестовые файлы, если Cloudflare недоступен.
DOWNLOAD_FALLBACKS = [
    ("fallback_10mb", "https://proof.ovh.net/files/10Mb.dat"),
]
UPLOAD_ENDPOINT = "https://httpbin.org/post"  # echo-сервис: примет наш POST

# Порты, которые имеет смысл прощупать TCP-коннектом, чтобы понять фильтрацию.
DEFAULT_PORTS = [443, 80, 8080, 8443, 22, 21, 25, 587, 993, 53]


# --------------------------------------------------------------------------- #
# Результат одной проверки
# --------------------------------------------------------------------------- #

@dataclass
class CheckResult:
    """Результат одной атомарной проверки (один домен — один тип — один порт)."""
    domain: str
    segment: str            # "ru" / "foreign" / "service"
    check_type: str         # dns / tcp / https / http / port / download / upload
    port: Optional[int]
    status: str             # одна из ALL_CATEGORIES
    http_code: Optional[int] = None
    elapsed_ms: Optional[float] = None
    bytes_transferred: Optional[int] = None
    speed_mbps: Optional[float] = None
    error: str = ""

    def as_row(self) -> Dict[str, object]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Классификация исключений
# --------------------------------------------------------------------------- #

def classify_exception(exc: BaseException) -> Tuple[str, str]:
    """Преобразовать исключение в (категория, человекочитаемое сообщение)."""
    msg = f"{type(exc).__name__}: {exc}"

    # Порядок важен: более специфичные типы — раньше.
    if isinstance(exc, socket.gaierror):
        return DNS_BLOCKED, msg
    if isinstance(exc, ssl.SSLError):
        # сюда же попадают SSLCertVerificationError и SSLEOFError
        return TLS_ERROR, msg
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TIMEOUT, msg
    if isinstance(exc, ConnectionRefusedError):
        return CONNECTION_REFUSED, msg
    if isinstance(exc, ConnectionResetError):
        return CONNECTION_RESET, msg
    if isinstance(exc, urllib.error.HTTPError):
        return HTTP_ERROR, msg
    if isinstance(exc, urllib.error.URLError):
        # внутри URLError может быть вложенная причина — разворачиваем
        reason = getattr(exc, "reason", None)
        if isinstance(reason, BaseException) and reason is not exc:
            return classify_exception(reason)
        return OTHER, msg
    if isinstance(exc, OSError):
        errno = getattr(exc, "errno", None)
        # ENETUNREACH=101, EHOSTUNREACH=113 (Linux)
        if errno in (101, 113):
            return NET_UNREACHABLE, msg
        return OTHER, msg
    return OTHER, msg


# --------------------------------------------------------------------------- #
# Атомарные проверки
# --------------------------------------------------------------------------- #

def resolve_host(domain: str, timeout: float) -> Tuple[List[str], float]:
    """Резолв имени -> (список IP с предпочтением IPv4, время в мс).

    Возвращает уникальные адреса, IPv4 первыми. Бросает исключение при ошибке
    DNS, чтобы вызывающий код классифицировал её как DNS_BLOCKED.
    """
    start = time.perf_counter()
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    finally:
        socket.setdefaulttimeout(old)
    elapsed = (time.perf_counter() - start) * 1000
    v4, v6 = [], []
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if family == socket.AF_INET and ip not in v4:
            v4.append(ip)
        elif family == socket.AF_INET6 and ip not in v6:
            v6.append(ip)
    return (v4 + v6), elapsed


def connect_ip(ip: str, port: int, timeout: float) -> socket.socket:
    """TCP-коннект к КОНКРЕТНОМУ ip:port одной попыткой.

    В отличие от socket.create_connection((host, port)) здесь нет перебора
    всех адресов домена, поэтому timeout — жёсткий потолок на одну проверку
    (а не timeout * число_адресов, что критично для доменов с IPv6).
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except Exception:
        sock.close()
        raise
    return sock


def check_dns(domain: str, segment: str, timeout: float) -> CheckResult:
    """Резолв доменного имени. Отдельно фиксирует блокировку DNS."""
    start = time.perf_counter()
    try:
        ips, elapsed = resolve_host(domain, timeout)
        return CheckResult(domain, segment, "dns", None, OK,
                           elapsed_ms=round(elapsed, 1),
                           error=f"{len(ips)} addr")
    except Exception as exc:  # noqa: BLE001 — нужно поймать любую сетевую ошибку
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(domain, segment, "dns", None, status,
                           elapsed_ms=round(elapsed, 1), error=msg)


def check_tcp(domain: str, segment: str, ip: str, port: int,
              timeout: float) -> CheckResult:
    """Чистый TCP-коннект на конкретный ip:port. Показывает фильтрацию портов."""
    start = time.perf_counter()
    try:
        sock = connect_ip(ip, port, timeout)
        sock.close()
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(domain, segment, "port", port, OK,
                           elapsed_ms=round(elapsed, 1))
    except Exception as exc:  # noqa: BLE001
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(domain, segment, "port", port, status,
                           elapsed_ms=round(elapsed, 1), error=msg)


def _read_status_line(sock: socket.socket) -> int:
    """Прочитать первую строку HTTP-ответа и вернуть код статуса."""
    buf = b""
    while b"\n" not in buf and len(buf) < 256:
        chunk = sock.recv(256 - len(buf))
        if not chunk:
            break
        buf += chunk
    line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    # формат: "HTTP/1.1 200 OK"
    parts = line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    raise http.client.BadStatusLine(line)


def _http_probe(domain: str, segment: str, ip: str, port: int, use_tls: bool,
                timeout: float) -> CheckResult:
    """HTTP(S)-проба через сокет, который мы контролируем сами.

    Коннект идёт к одному конкретному IP (без перебора адресов), таймаут —
    жёсткий потолок. Для TLS делается полноценный хендшейк с SNI и проверкой
    сертификата по имени домена.

    Для теста файрвола: ЛЮБОЙ полученный HTTP-код = трафик прошёл (OK),
    даже 4xx/5xx (код пишется в http_code). Блокировка — только сетевые/TLS
    ошибки.
    """
    check_type = "https" if use_tls else "http"
    start = time.perf_counter()
    sock = None
    try:
        sock = connect_ip(ip, port, timeout)
        sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=domain)
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        sock.sendall(request)
        code = _read_status_line(sock)
        elapsed = (time.perf_counter() - start) * 1000
        status = OK if code < 400 else HTTP_ERROR
        return CheckResult(domain, segment, check_type, port, status,
                           http_code=code, elapsed_ms=round(elapsed, 1))
    except Exception as exc:  # noqa: BLE001
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(domain, segment, check_type, port, status,
                           elapsed_ms=round(elapsed, 1), error=msg)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


def check_https(domain, segment, ip, timeout):
    """HTTPS-проба на 443 (включает TLS-хендшейк)."""
    return _http_probe(domain, segment, ip, 443, use_tls=True, timeout=timeout)


def check_http(domain, segment, ip, timeout):
    """HTTP-проба на 80."""
    return _http_probe(domain, segment, ip, 80, use_tls=False, timeout=timeout)


# --------------------------------------------------------------------------- #
# Тесты скачивания и отдачи
# --------------------------------------------------------------------------- #

def test_download(label: str, url: str, timeout: float,
                  max_bytes: int = 50_000_000) -> CheckResult:
    """Скачать файл, измерить скорость и факт успеха."""
    host = urllib.parse.urlparse(url).hostname or url
    start = time.perf_counter()
    total = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total >= max_bytes:
                    break
        elapsed = time.perf_counter() - start
        mbps = (total * 8 / 1_000_000) / elapsed if elapsed > 0 else 0.0
        return CheckResult(host, "service", "download", 443, OK,
                           elapsed_ms=round(elapsed * 1000, 1),
                           bytes_transferred=total,
                           speed_mbps=round(mbps, 2),
                           error=label)
    except Exception as exc:  # noqa: BLE001
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(url, "service", "download", 443, status,
                           elapsed_ms=round(elapsed, 1),
                           bytes_transferred=total,
                           error=f"{label}: {msg}")


def test_upload(size_bytes: int, timeout: float) -> CheckResult:
    """Отправить POST с телом заданного размера. Проверяет исходящий upload."""
    payload = b"x" * size_bytes
    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            UPLOAD_ENDPOINT, data=payload, method="POST",
            headers={"User-Agent": USER_AGENT,
                     "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            resp.read()
        elapsed = time.perf_counter() - start
        mbps = (size_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else 0.0
        status = OK if code < 400 else HTTP_ERROR
        return CheckResult(UPLOAD_ENDPOINT, "service", "upload", 443, status,
                           http_code=code, elapsed_ms=round(elapsed * 1000, 1),
                           bytes_transferred=size_bytes,
                           speed_mbps=round(mbps, 2),
                           error=f"{size_bytes} B")
    except Exception as exc:  # noqa: BLE001
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(UPLOAD_ENDPOINT, "service", "upload", 443, status,
                           elapsed_ms=round(elapsed, 1),
                           bytes_transferred=size_bytes,
                           error=f"{size_bytes} B: {msg}")


# --------------------------------------------------------------------------- #
# Прогон одного домена (DNS -> TCP -> HTTPS -> HTTP -> доп. порты)
# --------------------------------------------------------------------------- #

def probe_domain(domain: str, segment: str, timeout: float,
                 ports: List[int], delay: float) -> List[CheckResult]:
    """Полный набор проверок для одного домена.

    Сначала один раз резолвим имя. Если DNS не работает — дальнейшие сетевые
    проверки пропускаем (они всё равно были бы DNS_BLOCKED). Полученный IP
    переиспользуется во всех TCP/HTTP/HTTPS-проверках, чтобы таймаут был
    жёстким потолком на каждую проверку.
    """
    results: List[CheckResult] = []

    start = time.perf_counter()
    try:
        ips, dns_ms = resolve_host(domain, timeout)
        results.append(CheckResult(domain, segment, "dns", None, OK,
                                   elapsed_ms=round(dns_ms, 1),
                                   error=f"{len(ips)} addr"))
    except Exception as exc:  # noqa: BLE001
        status, msg = classify_exception(exc)
        elapsed = (time.perf_counter() - start) * 1000
        results.append(CheckResult(domain, segment, "dns", None, status,
                                   elapsed_ms=round(elapsed, 1), error=msg))
        if delay > 0:
            time.sleep(delay)
        return results

    ip = ips[0]  # предпочтительный адрес (IPv4 первым)
    results.append(check_https(domain, segment, ip, timeout))
    results.append(check_http(domain, segment, ip, timeout))
    for port in ports:
        if port in (80, 443):
            continue  # уже покрыты HTTP/HTTPS-пробами
        results.append(check_tcp(domain, segment, ip, port, timeout))

    if delay > 0:
        time.sleep(delay)
    return results


# --------------------------------------------------------------------------- #
# Загрузка списков доменов
# --------------------------------------------------------------------------- #

def load_domain_file(path: str) -> List[str]:
    """Прочитать список доменов из файла (по одному в строке, # — комментарий)."""
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # на случай если в файле полные URL — берём только хост
            line = line.replace("https://", "").replace("http://", "")
            line = line.split("/")[0].strip()
            if line:
                out.append(line.lower())
    # дедуп с сохранением порядка
    seen = set()
    uniq = []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def builtin_ru_domains() -> List[str]:
    """Встроенный сид-список реальных популярных RU-доменов."""
    return [
        "yandex.ru", "ya.ru", "mail.ru", "vk.com", "ok.ru", "dzen.ru",
        "gosuslugi.ru", "mos.ru", "nalog.gov.ru", "pochta.ru", "rzd.ru",
        "sberbank.ru", "online.sberbank.ru", "tinkoff.ru", "vtb.ru",
        "alfabank.ru", "raiffeisen.ru", "gazprombank.ru", "rosbank.ru",
        "mkb.ru", "sovcombank.ru", "psbank.ru", "open.ru",
        "avito.ru", "ozon.ru", "wildberries.ru", "aliexpress.ru",
        "market.yandex.ru", "dns-shop.ru", "mvideo.ru", "citilink.ru",
        "eldorado.ru", "lamoda.ru", "sbermegamarket.ru", "petrovich.ru",
        "leroymerlin.ru", "vseinstrumenti.ru", "onlinetrade.ru",
        "rbc.ru", "lenta.ru", "ria.ru", "tass.ru", "kommersant.ru",
        "gazeta.ru", "vesti.ru", "1tv.ru", "ntv.ru", "rt.com", "iz.ru",
        "kp.ru", "aif.ru", "mk.ru", "fontanka.ru", "vc.ru", "habr.com",
        "pikabu.ru", "drive2.ru", "kinopoisk.ru", "ivi.ru", "okko.tv",
        "rutube.ru", "smotrim.ru", "premier.one",
        "2gis.ru", "drom.ru", "auto.ru", "avto.ru", "hh.ru", "superjob.ru",
        "rabota.ru", "cian.ru", "domclick.ru", "sob.ru",
        "championat.com", "sports.ru", "sport-express.ru", "matchtv.ru",
        "banki.ru", "sravni.ru", "rambler.ru", "lpostm.ru",
        "megafon.ru", "mts.ru", "beeline.ru", "tele2.ru", "rt.ru",
        "rostelecom.ru", "aeroflot.ru", "s7.ru", "pobeda.aero",
        "tutu.ru", "aviasales.ru", "ostrovok.ru", "sutochno.ru",
        "vkusvill.ru", "perekrestok.ru", "magnit.ru", "lenta.com",
        "okeydostavka.ru", "samokat.ru", "delivery-club.ru",
        "edadeal.ru", "litres.ru", "labirint.ru", "chitai-gorod.ru",
        "stihi.ru", "proza.ru", "e1.ru", "ngs.ru", "74.ru", "59.ru",
        "irk.ru", "vladivostok.ru", "kuban.ru", "rostov.ru",
        "consultant.ru", "garant.ru", "kad.arbitr.ru", "sudrf.ru",
        "minfin.gov.ru", "cbr.ru", "rosreestr.gov.ru", "fns.ru",
        "mai.ru", "msu.ru", "hse.ru", "spbu.ru", "mephi.ru",
        "elibrary.ru", "cyberleninka.ru", "moodle.org",
        "rkn.gov.ru", "kremlin.ru", "government.ru", "duma.gov.ru",
    ]


def builtin_foreign_domains() -> List[str]:
    """Встроенный сид-список реальных популярных мировых доменов."""
    return [
        # поиск / большие платформы
        "google.com", "www.google.com", "youtube.com", "facebook.com",
        "instagram.com", "x.com", "twitter.com", "reddit.com",
        "wikipedia.org", "amazon.com", "bing.com", "yahoo.com",
        "duckduckgo.com", "linkedin.com", "pinterest.com", "tumblr.com",
        "quora.com", "medium.com", "wordpress.com", "blogger.com",
        # tech / разработка
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
        "stackexchange.com", "npmjs.com", "pypi.org", "docker.com",
        "kubernetes.io", "cloudflare.com", "digitalocean.com", "heroku.com",
        "vercel.com", "netlify.com", "mozilla.org", "apache.org",
        "python.org", "nodejs.org", "rust-lang.org", "golang.org",
        "developer.mozilla.org", "w3.org", "ietf.org",
        # облака / IT-гиганты
        "microsoft.com", "azure.com", "office.com", "live.com",
        "apple.com", "icloud.com", "oracle.com", "ibm.com", "sap.com",
        "intel.com", "nvidia.com", "amd.com", "qualcomm.com",
        "samsung.com", "sony.com", "lg.com", "dell.com", "hp.com",
        "lenovo.com", "asus.com", "cisco.com", "vmware.com",
        "aws.amazon.com", "console.cloud.google.com",
        # медиа / новости
        "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
        "washingtonpost.com", "reuters.com", "apnews.com", "bloomberg.com",
        "forbes.com", "wsj.com", "ft.com", "economist.com", "time.com",
        "nationalgeographic.com", "wired.com", "techcrunch.com",
        "theverge.com", "arstechnica.com", "engadget.com",
        # развлечения / стриминг
        "netflix.com", "spotify.com", "twitch.tv", "soundcloud.com",
        "vimeo.com", "dailymotion.com", "imdb.com", "hulu.com",
        "disneyplus.com", "primevideo.com", "deezer.com",
        # коммуникации
        "telegram.org", "web.telegram.org", "whatsapp.com", "discord.com",
        "slack.com", "zoom.us", "skype.com", "signal.org", "meet.google.com",
        "teams.microsoft.com", "messenger.com",
        # почта / файлы / продуктивность
        "gmail.com", "outlook.com", "proton.me", "dropbox.com",
        "drive.google.com", "onedrive.live.com", "box.com", "mega.nz",
        "notion.so", "trello.com", "asana.com", "atlassian.com",
        "figma.com", "canva.com", "adobe.com", "miro.com",
        # e-commerce / финансы
        "ebay.com", "aliexpress.com", "alibaba.com", "etsy.com",
        "walmart.com", "target.com", "bestbuy.com", "paypal.com",
        "stripe.com", "visa.com", "mastercard.com", "coinbase.com",
        "binance.com", "booking.com", "airbnb.com", "expedia.com",
        "tripadvisor.com", "uber.com", "lyft.com",
        # Азия
        "baidu.com", "taobao.com", "tmall.com", "jd.com", "qq.com",
        "weibo.com", "bilibili.com", "163.com", "sina.com.cn",
        "naver.com", "daum.net", "rakuten.co.jp", "yahoo.co.jp",
        "tiktok.com", "douyin.com", "line.me",
        # Европа / прочее
        "spiegel.de", "lemonde.fr", "elpais.com", "corriere.it",
        "marca.com", "leboncoin.fr", "bild.de", "heise.de",
        # CDN / инфра (часто отдельно фильтруются)
        "cloudfront.net", "akamai.com", "fastly.com", "jsdelivr.net",
        "cdnjs.cloudflare.com", "unpkg.com", "googleapis.com",
        "gstatic.com", "fbcdn.net", "twimg.com", "ytimg.com",
    ]


def resolve_domain_lists(args) -> Tuple[List[str], List[str]]:
    """Определить итоговые списки RU и иностранных доменов с учётом файлов."""
    ru_file = os.path.join(args.domains_dir, "domains_ru.txt")
    foreign_file = os.path.join(args.domains_dir, "domains_foreign.txt")

    if os.path.isfile(ru_file):
        ru = load_domain_file(ru_file)
        logging.info("RU-список загружен из файла: %s (%d доменов)", ru_file, len(ru))
    else:
        ru = builtin_ru_domains()
        logging.info("RU-список: встроенный сид (%d доменов). "
                     "Для полного прогона положите %s", len(ru), ru_file)

    if os.path.isfile(foreign_file):
        foreign = load_domain_file(foreign_file)
        logging.info("Иностранный список загружен из файла: %s (%d доменов)",
                     foreign_file, len(foreign))
    else:
        foreign = builtin_foreign_domains()
        logging.info("Иностранный список: встроенный сид (%d доменов). "
                     "Для полного прогона положите %s", len(foreign), foreign_file)

    if args.limit:
        ru = ru[:args.limit]
        foreign = foreign[:args.limit]
    return ru, foreign


# --------------------------------------------------------------------------- #
# Запуск прогона по доменам
# --------------------------------------------------------------------------- #

def run_domain_sweep(domains: List[Tuple[str, str]], args) -> List[CheckResult]:
    """Параллельный прогон проверок по списку (домен, сегмент)."""
    results: List[CheckResult] = []
    total = len(domains)
    done = 0
    lock = threading.Lock()

    logging.info("Старт прогона: %d доменов, %d воркеров, таймаут %.1fs",
                 total, args.workers, args.timeout)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(probe_domain, dom, seg, args.timeout,
                        args.ports, args.delay): (dom, seg)
            for dom, seg in domains
        }
        for fut in as_completed(futures):
            dom, _ = futures[fut]
            try:
                results.extend(fut.result())
            except Exception as exc:  # noqa: BLE001
                logging.warning("Ошибка при проверке %s: %s", dom, exc)
            with lock:
                done += 1
                if done % 100 == 0 or done == total:
                    logging.info("Прогресс: %d / %d доменов", done, total)
    return results


def run_transfer_tests(args) -> List[CheckResult]:
    """Тесты скачивания и отдачи (отдельно от массового прогона доменов)."""
    results: List[CheckResult] = []

    if not args.skip_download:
        logging.info("Тест скачивания...")
        endpoints = list(DOWNLOAD_ENDPOINTS)
        for label, url in endpoints:
            res = test_download(label, url, timeout=max(args.timeout, 30))
            results.append(res)
            logging.info("  download %-12s -> %s (%.2f Mbps, %s B)",
                         label, res.status, res.speed_mbps or 0,
                         res.bytes_transferred)
        # если все основные упали — пробуем резерв
        if all(r.status != OK for r in results):
            for label, url in DOWNLOAD_FALLBACKS:
                res = test_download(label, url, timeout=max(args.timeout, 30))
                results.append(res)
                logging.info("  download(fallback) %-12s -> %s", label, res.status)

    if not args.skip_upload:
        logging.info("Тест отдачи (upload)...")
        for size in (100_000, 1_000_000):  # 100 КБ и 1 МБ
            res = test_upload(size, timeout=max(args.timeout, 30))
            results.append(res)
            logging.info("  upload %-9d B -> %s (%.2f Mbps)",
                         size, res.status, res.speed_mbps or 0)
    return results


# --------------------------------------------------------------------------- #
# Отчёты
# --------------------------------------------------------------------------- #

def write_csv(results: List[CheckResult], path: str) -> None:
    """Подробный CSV со всеми проверками."""
    fields = ["domain", "segment", "check_type", "port", "status",
              "http_code", "elapsed_ms", "bytes_transferred",
              "speed_mbps", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow(r.as_row())


def build_summary(results: List[CheckResult], started: str,
                  finished: str) -> Dict[str, object]:
    """Свести статистику для JSON-отчёта и stdout."""
    def empty_counter() -> Dict[str, int]:
        return {c: 0 for c in ALL_CATEGORIES}

    summary: Dict[str, object] = {
        "started": started,
        "finished": finished,
        "total_checks": len(results),
        "by_segment": {},
        "by_check_type": {},
        "transfer": {},
    }

    # по сегментам
    for seg in ("ru", "foreign"):
        seg_results = [r for r in results if r.segment == seg
                       and r.check_type in ("https", "http", "dns")]
        counter = empty_counter()
        for r in seg_results:
            counter[r.status] = counter.get(r.status, 0) + 1
        total = sum(counter.values())
        ok = counter[OK]
        summary["by_segment"][seg] = {
            "checks": total,
            "ok": ok,
            "ok_pct": round(100 * ok / total, 1) if total else 0.0,
            "categories": counter,
        }

    # по типам проверок
    types = sorted({r.check_type for r in results})
    for t in types:
        t_results = [r for r in results if r.check_type == t]
        counter = empty_counter()
        for r in t_results:
            counter[r.status] = counter.get(r.status, 0) + 1
        summary["by_check_type"][t] = counter

    # порты
    port_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        if r.check_type == "port" and r.port is not None:
            key = str(r.port)
            port_stats.setdefault(key, empty_counter())
            port_stats[key][r.status] += 1
    summary["by_port"] = port_stats

    # скорости download/upload
    dl = [r for r in results if r.check_type == "download" and r.status == OK
          and r.speed_mbps]
    ul = [r for r in results if r.check_type == "upload" and r.status == OK
          and r.speed_mbps]
    if dl:
        speeds = [r.speed_mbps for r in dl]
        summary["transfer"]["download_mbps"] = {
            "mean": round(statistics.mean(speeds), 2),
            "median": round(statistics.median(speeds), 2),
            "max": round(max(speeds), 2),
            "samples": len(speeds),
        }
    if ul:
        speeds = [r.speed_mbps for r in ul]
        summary["transfer"]["upload_mbps"] = {
            "mean": round(statistics.mean(speeds), 2),
            "median": round(statistics.median(speeds), 2),
            "samples": len(speeds),
        }
    summary["transfer"]["download_ok"] = bool(dl)
    summary["transfer"]["upload_ok"] = bool(ul)
    return summary


def print_human_summary(summary: Dict[str, object]) -> None:
    """Краткий человекочитаемый итог в stdout."""
    line = "=" * 64
    print("\n" + line)
    print("ИТОГ ТЕСТА ФАЙРВОЛА")
    print(line)
    print(f"Проверок всего: {summary['total_checks']}")
    print(f"Старт:  {summary['started']}")
    print(f"Финиш:  {summary['finished']}")

    print("\nДоступность по сегментам (dns/http/https):")
    for seg, data in summary["by_segment"].items():
        name = "RU-сегмент" if seg == "ru" else "Иностранный"
        print(f"  {name:14s}: {data['ok_pct']:5.1f}% OK "
              f"({data['ok']}/{data['checks']})")
        # топ причин блокировки
        cats = {k: v for k, v in data["categories"].items()
                if k != OK and v > 0}
        if cats:
            top = sorted(cats.items(), key=lambda kv: -kv[1])[:4]
            blocked = ", ".join(f"{k}={v}" for k, v in top)
            print(f"                  блокировки: {blocked}")

    print("\nФильтрация по портам (TCP-коннект):")
    for port, counter in sorted(summary.get("by_port", {}).items(),
                                key=lambda kv: int(kv[0])):
        total = sum(counter.values())
        ok = counter.get(OK, 0)
        pct = round(100 * ok / total, 1) if total else 0.0
        print(f"  порт {port:>5}: {pct:5.1f}% открыто ({ok}/{total})")

    tr = summary.get("transfer", {})
    print("\nСкачивание / отдача:")
    if tr.get("download_mbps"):
        d = tr["download_mbps"]
        print(f"  download: медиана {d['median']} Mbps, "
              f"max {d['max']} Mbps ({d['samples']} файлов)")
    else:
        print(f"  download: {'OK' if tr.get('download_ok') else 'НЕ ПРОШЁЛ'}")
    if tr.get("upload_mbps"):
        u = tr["upload_mbps"]
        print(f"  upload:   медиана {u['median']} Mbps ({u['samples']} попыток)")
    else:
        print(f"  upload:   {'OK' if tr.get('upload_ok') else 'НЕ ПРОШЁЛ'}")
    print(line + "\n")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_ports(value: str) -> List[int]:
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(int(part))
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Тестирование сетевых возможностей файрвола без прав root.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--workers", type=int, default=40,
                   help="число параллельных воркеров")
    p.add_argument("--timeout", type=float, default=8.0,
                   help="таймаут на одну сетевую операцию, сек")
    p.add_argument("--delay", type=float, default=0.0,
                   help="пауза после каждого домена, сек (вежливость к сайтам)")
    p.add_argument("--output-dir", default="./fw_test_results",
                   help="папка для отчётов")
    p.add_argument("--domains-dir", default=".",
                   help="папка с domains_ru.txt / domains_foreign.txt")
    p.add_argument("--segment", choices=["ru", "foreign", "all"], default="all",
                   help="какой сегмент проверять")
    p.add_argument("--limit", type=int, default=0,
                   help="ограничить число доменов на сегмент (0 = без лимита)")
    p.add_argument("--ports", type=parse_ports,
                   default=DEFAULT_PORTS,
                   help="список TCP-портов через запятую")
    p.add_argument("--skip-download", action="store_true",
                   help="не тестировать скачивание")
    p.add_argument("--skip-upload", action="store_true",
                   help="не тестировать отдачу (upload)")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="уровень логирования")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")

    os.makedirs(args.output_dir, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    ru, foreign = resolve_domain_lists(args)

    domains: List[Tuple[str, str]] = []
    if args.segment in ("ru", "all"):
        domains += [(d, "ru") for d in ru]
    if args.segment in ("foreign", "all"):
        domains += [(d, "foreign") for d in foreign]

    logging.info("К проверке: %d доменов (RU=%d, foreign=%d)",
                 len(domains),
                 sum(1 for _, s in domains if s == "ru"),
                 sum(1 for _, s in domains if s == "foreign"))

    results = run_domain_sweep(domains, args)
    results += run_transfer_tests(args)

    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(args.output_dir, f"fw_test_{ts}.csv")
    json_path = os.path.join(args.output_dir, f"fw_test_{ts}_summary.json")

    write_csv(results, csv_path)
    summary = build_summary(results, started, finished)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    print_human_summary(summary)
    logging.info("Подробный отчёт: %s", csv_path)
    logging.info("Сводка (JSON):   %s", json_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
