#!/usr/bin/env python3
"""
Высокопараллельный пикер VLESS/VMess/Trojan для Avito (v7).

Новое в v7:
  • Cooldown-механика для забаненных (Avito банит временно)
  • Забаненные серверы возвращаются в пул через BAN_COOLDOWN секунд
  • reset_expired_bans() вызывается в pick/next/stats
  • pick/next пропускают тех, кто сейчас в cooldown
"""
import os
import sys
import json
import time
import socket
import random
import signal
import hashlib
import ipaddress
import subprocess
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from threading import Lock
from pathlib import Path

# ══════════════════════════════════════════════════════════════
#  ИСТОЧНИКИ
# ══════════════════════════════════════════════════════════════
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/trojan.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/trojan.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/trojan.txt",
]

# ══════════════════════════════════════════════════════════════
#  ПУТИ
# ══════════════════════════════════════════════════════════════
XRAY_BIN         = "xray_bin/xray"
WORKING_FILE     = "data/working_servers.json"
TESTED_FILE      = "data/tested_servers.txt"
CURRENT_IDX_FILE = "data/current_server_idx"
TEST_LOG_FILE    = "data/test_log.txt"
TMP_DIR          = Path("data/tmp_xray")
XRAY_CONFIG      = "data/xray_config.json"

# ══════════════════════════════════════════════════════════════
#  ПАРАЛЛЕЛЬНОСТЬ
# ══════════════════════════════════════════════════════════════
NUM_WORKERS      = 60
TCP_THREADS      = 400
PORT_BASE        = 10800

# ══════════════════════════════════════════════════════════════
#  ТАЙМИНГИ
# ══════════════════════════════════════════════════════════════
TCP_TIMEOUT         = 2
XRAY_WAIT           = 3
HTTP_TIMEOUT        = 8
STABILITY_CHECKS    = 3
STABILITY_PAUSE     = 2
FLUSH_TESTED_EVERY  = 60
BUILD_TIME_BUDGET   = 999_999_999
MAX_WINNERS         = 999_999

# ══════════════════════════════════════════════════════════════
#  COOLDOWN ДЛЯ ЗАБАНЕННЫХ
# ══════════════════════════════════════════════════════════════
# Avito банит обычно на 10-60 минут. Ставим 30 мин.
# Через это время сервер снова пробуется: может, уже разблокирован.
BAN_COOLDOWN_SEC = 30 * 60
# Если сервер уже банился N раз — увеличиваем cooldown (backoff)
BAN_COOLDOWN_MULTIPLIER = 2.0
BAN_COOLDOWN_MAX = 4 * 60 * 60   # максимум 4 часа

# ══════════════════════════════════════════════════════════════
#  CLOUDFLARE
# ══════════════════════════════════════════════════════════════
CLOUDFLARE_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
_CF_NETS = [ipaddress.ip_network(c) for c in CLOUDFLARE_RANGES]

# ══════════════════════════════════════════════════════════════
#  ТЕСТОВЫЙ URL AVITO
# ══════════════════════════════════════════════════════════════
TEST_URL = (
    "https://www.avito.ru/web/1/js/items"
    "?categoryId=6&localPriority=0&locationId=637640"
    "&presentationType=serp&query=mac+mini+m4&sort=default&page=1"
)
CURL_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"
)

# ══════════════════════════════════════════════════════════════
#  ГЛОБАЛЬНОЕ СОСТОЯНИЕ
# ══════════════════════════════════════════════════════════════
PORT_POOL    = Queue()
for i in range(NUM_WORKERS):
    PORT_POOL.put(PORT_BASE + i)

TESTED_LOCK  = Lock()
TESTED_SET   = set()

WINNERS_LOCK = Lock()
WINNERS      = []

STATS_LOCK   = Lock()
STATS        = {"OK": 0, "IP_BAN": 0, "BLOCK": 0, "DEAD": 0,
                "OTHER": 0, "ERROR": 0, "XRAY_FAIL": 0}

LOG_LOCK     = Lock()
LOG_LINES    = []

STOP_FLAG    = False
LAST_FLUSH   = [time.time()]


# ══════════════════════════════════════════════════════════════
#  SIGNAL HANDLER
# ══════════════════════════════════════════════════════════════
def _sig_handler(sig, frame):
    print(f"\n⚠️ Получен сигнал {sig}, сохраняю состояние...")
    try:
        with TESTED_LOCK:
            _save_tested_unsafe()
        with WINNERS_LOCK:
            if WINNERS:
                _save_working_unsafe(WINNERS)
                print(f"💾 Сохранено {len(WINNERS)} рабочих")
    except Exception as e:
        print(f"Ошибка при сохранении: {e}")
    sys.exit(0)


signal.signal(signal.SIGTERM, _sig_handler)
signal.signal(signal.SIGINT, _sig_handler)


# ══════════════════════════════════════════════════════════════
#  CLOUDFLARE-ФИЛЬТР
# ══════════════════════════════════════════════════════════════
def is_cloudflare_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _CF_NETS)
    except ValueError:
        pass
    try:
        prev = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2)
        try:
            _, _, ips = socket.gethostbyname_ex(host)
        finally:
            socket.setdefaulttimeout(prev)
        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if any(ip in net for net in _CF_NETS):
                    return True
            except ValueError:
                continue
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════
#  ЗАГРУЗКА / ПАРСИНГ
# ══════════════════════════════════════════════════════════════
def fetch_list(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "ignore").splitlines()
    except Exception as e:
        print(f"  ⚠️ {url}: {e}")
        return []


def parse_vless(url):
    if not url.startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlparse(url)
        p = dict(urllib.parse.parse_qsl(u.query))
        return {
            "type": "vless",
            "uuid": urllib.parse.unquote(u.username or ""),
            "host": u.hostname,
            "port": u.port,
            "params": p,
            "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
            "raw": url,
        }
    except Exception:
        return None


def parse_vmess(url):
    import base64
    if not url.startswith("vmess://"):
        return None
    try:
        b64 = url[8:]
        b64 += "=" * (-len(b64) % 4)
        d = json.loads(base64.b64decode(b64).decode("utf-8"))
        return {
            "type": "vmess",
            "uuid": d.get("id", ""),
            "host": d.get("add", ""),
            "port": int(d.get("port", 0)),
            "params": {
                "security": "tls" if d.get("tls") == "tls" else "none",
                "type": d.get("net", "tcp"),
                "path": d.get("path", "/"),
                "host": d.get("host", ""),
                "sni": d.get("sni", d.get("host", "")),
                "fp": "chrome",
            },
            "name": d.get("ps", ""),
            "raw": url,
        }
    except Exception:
        return None


def parse_trojan(url):
    if not url.startswith("trojan://"):
        return None
    try:
        u = urllib.parse.urlparse(url)
        p = dict(urllib.parse.parse_qsl(u.query))
        return {
            "type": "trojan",
            "password": urllib.parse.unquote(u.username or ""),
            "host": u.hostname,
            "port": u.port,
            "params": p,
            "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
            "raw": url,
        }
    except Exception:
        return None


def parse_any(url):
    for fn in (parse_vless, parse_vmess, parse_trojan):
        v = fn(url)
        if v:
            return v
    return None


def is_usable(v):
    if not v or not v.get("host") or not v.get("port"):
        return False
    p = v.get("params", {})
    if p.get("security", "none") == "reality" and not p.get("pbk"):
        return False
    if p.get("type", "tcp") == "grpc" and not p.get("serviceName"):
        return False
    return True


def server_hash(v):
    k = f"{v['type']}|{v['host']}|{v['port']}|{v.get('uuid') or v.get('password')}"
    return hashlib.sha1(k.encode()).hexdigest()[:16]


# ══════════════════════════════════════════════════════════════
#  XRAY-КОНФИГ
# ══════════════════════════════════════════════════════════════
def build_xray_config(v, port):
    t, p = v["type"], v.get("params", {})
    net, sec = p.get("type", "tcp"), p.get("security", "none")

    stream = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {
            "path": p.get("path", "/"),
            "headers": {"Host": p.get("host", v["host"])},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    elif net == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [p.get("path", "/")],
                    "headers": {"Host": [p.get("host", v["host"])]},
                },
            }
        }

    if sec == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": p.get("sni", v["host"]),
            "fingerprint": p.get("fp", "chrome"),
            "allowInsecure": p.get("allowInsecure", "0") == "1",
        }
    elif sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
        }

    if t == "vless":
        out = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": v["host"],
                    "port": int(v["port"]),
                    "users": [{
                        "id": v["uuid"],
                        "encryption": "none",
                        "flow": p.get("flow", ""),
                    }],
                }],
            },
            "streamSettings": stream,
        }
    elif t == "vmess":
        out = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": v["host"],
                    "port": int(v["port"]),
                    "users": [{
                        "id": v["uuid"],
                        "alterId": 0,
                        "security": "auto",
                    }],
                }],
            },
            "streamSettings": stream,
        }
    elif t == "trojan":
        out = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": v["host"],
                    "port": int(v["port"]),
                    "password": v["password"],
                }],
            },
            "streamSettings": stream,
        }
    else:
        raise ValueError(f"Unknown type: {t}")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "http",
            "settings": {"timeout": 0},
        }],
        "outbounds": [out],
    }


# ══════════════════════════════════════════════════════════════
#  TCP PING
# ══════════════════════════════════════════════════════════════
def tcp_ping(v):
    try:
        s = socket.create_connection((v["host"], v["port"]), timeout=TCP_TIMEOUT)
        s.close()
        return v, True
    except Exception:
        return v, False


def ping_all(servers):
    alive = []
    total = len(servers)
    print(f"🔍 TCP-ping: {total} серверов, {TCP_THREADS} потоков")
    with ThreadPoolExecutor(max_workers=TCP_THREADS) as ex:
        futs = {ex.submit(tcp_ping, v): v for v in servers}
        done = 0
        for f in as_completed(futs):
            done += 1
            v, ok = f.result()
            if ok:
                alive.append(v)
            if done % 1000 == 0 or done == total:
                print(f"   [{done}/{total}] живых: {len(alive)}")
    return alive


# ══════════════════════════════════════════════════════════════
#  XRAY WORKER
# ══════════════════════════════════════════════════════════════
def start_xray(v, port, cfg_path, log_path):
    Path(cfg_path).write_text(json.dumps(build_xray_config(v, port), indent=2))
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            [XRAY_BIN, "-c", cfg_path],
            stdout=log, stderr=log,
        )
    for _ in range(XRAY_WAIT * 5):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            time.sleep(0.2)
            return proc
        except Exception:
            time.sleep(0.2)
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return None


def stop_xray(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def curl_avito_via_port(port):
    cmd = [
        "curl", "-sS", "--max-time", str(HTTP_TIMEOUT),
        "-x", f"http://127.0.0.1:{port}",
        "-H", "Accept: application/json, text/plain, */*",
        "-H", "Referer: https://www.avito.ru/",
        "-H", f"User-Agent: {CURL_UA}",
        "-w", "\n__HTTP_CODE__%{http_code}",
        TEST_URL,
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=HTTP_TIMEOUT + 3,
        )
        out = r.stdout
        if "__HTTP_CODE__" in out:
            body, _, code = out.rpartition("__HTTP_CODE__")
        else:
            body, code = out, ""
        body = body.strip()

        if code == "200" and body.startswith(("{", "[")):
            return "OK", f"200, len={len(body)}"
        if "Доступ ограничен" in body or "проблема с IP" in body:
            return "IP_BAN", f"{code}, firewall"
        if code in ("403", "429", "439"):
            return "BLOCK", f"{code}"
        if code in ("000", ""):
            return "DEAD", "no response"
        return "OTHER", f"{code}, {body[:60]!r}"
    except subprocess.TimeoutExpired:
        return "DEAD", "timeout"
    except Exception as e:
        return "ERROR", str(e)


def read_log_tail(path, n=3):
    try:
        with open(path) as f:
            return " | ".join(l.strip() for l in f.readlines()[-n:] if l.strip())
    except Exception:
        return ""


def test_one_server(v):
    try:
        port = PORT_POOL.get(timeout=120)
    except Empty:
        return "ERROR", "no free port", -1, 0

    try:
        cfg_path = TMP_DIR / f"cfg_{port}.json"
        log_path = TMP_DIR / f"log_{port}.log"

        proc = start_xray(v, port, cfg_path, log_path)
        if not proc:
            tail = read_log_tail(log_path)
            return "XRAY_FAIL", f"xray fail | {tail}", port, 0

        try:
            results = []
            last_info = ""
            for i in range(STABILITY_CHECKS):
                verdict, info = curl_avito_via_port(port)
                results.append(verdict)
                last_info = info
                if i < STABILITY_CHECKS - 1:
                    time.sleep(STABILITY_PAUSE)

            ok_count = sum(1 for r in results if r == "OK")

            if ok_count >= 2:
                return "OK", f"stable {ok_count}/{STABILITY_CHECKS} | {last_info}", port, ok_count
            if ok_count == 1:
                return "OK", f"unstable 1/{STABILITY_CHECKS} | {last_info}", port, 1

            common = Counter(results).most_common(1)[0][0]
            return common, f"0/{STABILITY_CHECKS} | {last_info}", port, 0
        finally:
            stop_xray(proc)
    finally:
        try:
            (TMP_DIR / f"cfg_{port}.json").unlink(missing_ok=True)
            (TMP_DIR / f"log_{port}.log").unlink(missing_ok=True)
        except Exception:
            pass
        PORT_POOL.put(port)


# ══════════════════════════════════════════════════════════════
#  ХРАНИЛИЩА
# ══════════════════════════════════════════════════════════════
def _save_tested_unsafe():
    tmp = Path(str(TESTED_FILE) + ".tmp")
    tmp.write_text("\n".join(sorted(TESTED_SET)))
    tmp.replace(TESTED_FILE)


def _save_working_unsafe(servers):
    tmp = Path(str(WORKING_FILE) + ".tmp")
    tmp.write_text(json.dumps(servers, indent=2))
    tmp.replace(WORKING_FILE)


def save_working_incremental(servers):
    _save_working_unsafe(servers)


def load_tested():
    if not Path(TESTED_FILE).exists():
        return set()
    return set(Path(TESTED_FILE).read_text().splitlines())


def load_working():
    if not Path(WORKING_FILE).exists():
        return []
    try:
        return json.loads(Path(WORKING_FILE).read_text())
    except Exception:
        return []


def load_current_idx():
    if not Path(CURRENT_IDX_FILE).exists():
        return 0
    try:
        return int(Path(CURRENT_IDX_FILE).read_text().strip() or "0")
    except Exception:
        return 0


def save_current_idx(idx):
    Path(CURRENT_IDX_FILE).write_text(str(idx))


def activate_server(v):
    Path(XRAY_CONFIG).write_text(json.dumps(build_xray_config(v, 1080), indent=2))


def load_all_servers():
    seen, servers = set(), []
    for src in SOURCES:
        print(f"📥 {src}")
        for line in fetch_list(src):
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            v = parse_any(line)
            if is_usable(v):
                servers.append(v)
    return servers


# ══════════════════════════════════════════════════════════════
#  COOLDOWN-МЕХАНИКА
# ══════════════════════════════════════════════════════════════
def _get_cooldown_for(s: dict) -> int:
    """
    Возвращает длительность cooldown для сервера.
    Базовая = BAN_COOLDOWN_SEC, растёт с числом предыдущих банов.
    """
    ban_count = s.get("ban_count", 0)
    cooldown = BAN_COOLDOWN_SEC * (BAN_COOLDOWN_MULTIPLIER ** ban_count)
    return min(int(cooldown), BAN_COOLDOWN_MAX)


def is_server_available(s: dict, now: float | None = None) -> bool:
    """
    True, если сервер можно использовать СЕЙЧАС:
      • никогда не банился, ИЛИ
      • cooldown истёк
    """
    if now is None:
        now = time.time()

    if not s.get("banned_by_avito"):
        return True

    banned_at = s.get("banned_at", 0)
    cooldown = _get_cooldown_for(s)
    return (now - banned_at) >= cooldown


def reset_expired_bans(servers: list[dict]) -> tuple[list[dict], int]:
    """
    Снимает метку banned_by_avito с тех, у кого cooldown истёк.
    Возвращает (обновлённый_список, сколько_разбанено).
    """
    now = time.time()
    unblocked = 0
    for s in servers:
        if s.get("banned_by_avito") and is_server_available(s, now):
            s["banned_by_avito"] = False
            s["unblocked_at"] = int(now)
            unblocked += 1
    return servers, unblocked


def mark_banned(server_or_hash) -> bool:
    """Помечает сервер как забаненный Avito, увеличивает ban_count."""
    if isinstance(server_or_hash, dict):
        h = server_hash(server_or_hash)
    else:
        h = server_or_hash

    servers = load_working()
    changed = False
    now = int(time.time())
    for s in servers:
        if server_hash(s) == h:
            if s.get("banned_by_avito"):
                # Уже забанен — не трогаем
                return False
            s["banned_by_avito"] = True
            s["banned_at"] = now
            s["ban_count"] = s.get("ban_count", 0) + 1
            changed = True
            break

    if changed:
        _save_working_unsafe(servers)
        cooldown = _get_cooldown_for(next(s for s in servers if server_hash(s) == h))
        print(f"💀 Забанен: {h} (cooldown {cooldown // 60} мин)")
    return changed


def _pick_next_available(start_idx: int):
    """
    Возвращает индекс следующего доступного сервера.
    Сначала сбрасывает истёкшие баны.
    """
    servers = load_working()
    if not servers:
        return None, servers

    servers, unblocked = reset_expired_bans(servers)
    if unblocked:
        _save_working_unsafe(servers)
        print(f"♻️ Разбанено (cooldown истёк): {unblocked}")

    n = len(servers)
    # Приоритет 1: доступные серверы (не в бане)
    for offset in range(n):
        idx = (start_idx + offset) % n
        if is_server_available(servers[idx]):
            return idx, servers

    # Приоритет 2: если все в бане — берём того, у кого cooldown истекает раньше всех
    print("⚠️ Все серверы в cooldown — беру тот, что разблокируется раньше всех")
    best_idx = min(
        range(n),
        key=lambda i: servers[i].get("banned_at", 0) + _get_cooldown_for(servers[i]),
    )
    # Снимаем метку, чтобы использовать
    servers[best_idx]["banned_by_avito"] = False
    _save_working_unsafe(servers)
    return best_idx, servers


# ══════════════════════════════════════════════════════════════
#  WORKER
# ══════════════════════════════════════════════════════════════
def _maybe_flush_tested():
    now = time.time()
    if now - LAST_FLUSH[0] > FLUSH_TESTED_EVERY:
        try:
            with TESTED_LOCK:
                _save_tested_unsafe()
        except Exception as e:
            print(f"⚠️ Ошибка flush tested: {e}")
        LAST_FLUSH[0] = now


def worker(v, idx, total):
    global STOP_FLAG
    if STOP_FLAG:
        return

    name = (v["name"] or v["host"])[:50]
    verdict, info, port, stability = test_one_server(v)

    with TESTED_LOCK:
        TESTED_SET.add(server_hash(v))

    with STATS_LOCK:
        STATS[verdict] = STATS.get(verdict, 0) + 1

    with LOG_LOCK:
        LOG_LINES.append(
            f"[{idx}] {verdict} {v['type']} {v['host']}:{v['port']} {name} | {info}"
        )

    if verdict not in ("DEAD",):
        print(f"[{idx}/{total}] {verdict}: [{v['type']}] {v['host']}:{v['port']} — {name}")
        if verdict in ("OK", "OTHER", "ERROR") and info:
            print(f"          → {info}")

    if verdict == "OK":
        v_copy = dict(v)
        v_copy["stability"] = stability
        v_copy["banned_by_avito"] = False
        v_copy["ban_count"] = 0
        with WINNERS_LOCK:
            existing_hashes = {server_hash(w) for w in WINNERS}
            if server_hash(v_copy) not in existing_hashes:
                WINNERS.append(v_copy)
                WINNERS.sort(key=lambda x: x.get("stability", 0), reverse=True)
                save_working_incremental(WINNERS)
                print(f"   ⭐ РАБОЧИЙ (stability={stability})! Всего: {len(WINNERS)}")
            else:
                print(f"   ♻️ Уже был в списке, пропускаю")

            if len(WINNERS) >= MAX_WINNERS:
                STOP_FLAG = True
                print(f"\n✅ Достигли {MAX_WINNERS} рабочих — останавливаю тест")

    _maybe_flush_tested()


# ══════════════════════════════════════════════════════════════
#  РЕЖИМЫ
# ══════════════════════════════════════════════════════════════
def mode_build():
    global STOP_FLAG
    start_ts = time.time()
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    all_servers = load_all_servers()
    print(f"\n   всего пригодных серверов: {len(all_servers)}")

    tested = load_tested()
    print(f"   уже тестировалось: {len(tested)}")

    for h in tested:
        TESTED_SET.add(h)

    fresh = [v for v in all_servers if server_hash(v) not in TESTED_SET]
    print(f"   новых: {len(fresh)}")

    if not fresh:
        print("⚠️ Все протестированы — беру 2000 случайных")
        random.shuffle(all_servers)
        fresh = all_servers[:2000]

    random.shuffle(fresh)

    alive = ping_all(fresh)
    print(f"   TCP-живых: {len(alive)}")
    if not alive:
        print("❌ ни один не отвечает на TCP")
        sys.exit(1)

    before = len(alive)
    print(f"🌐 Отсеиваю Cloudflare...")
    alive = [v for v in alive if not is_cloudflare_host(v["host"])]
    print(f"   отфильтровано: {before - len(alive)}, осталось: {len(alive)}")

    if not alive:
        print("❌ после фильтра CF ничего не осталось")
        sys.exit(1)

    random.shuffle(alive)

    print(f"\n🧪 Avito-тест: {len(alive)} серверов, {NUM_WORKERS} параллельных Xray")
    print(f"   stability: {STABILITY_CHECKS} запросов с паузой {STABILITY_PAUSE}с")
    print(f"   лимитов по времени/количеству нет\n")

    total = len(alive)
    done_count = [0]
    done_lock = Lock()
    last_progress = [time.time()]

    def _run(args):
        idx, v = args
        if STOP_FLAG:
            return
        worker(v, idx, total)
        with done_lock:
            done_count[0] += 1
            if time.time() - last_progress[0] > 30 or done_count[0] == total:
                last_progress[0] = time.time()
                with STATS_LOCK:
                    s = dict(STATS)
                print(f"\n📊 Прогресс: {done_count[0]}/{total} "
                      f"({done_count[0] * 100 / total:.1f}%) | "
                      f"OK={s['OK']} IP_BAN={s['IP_BAN']} BLOCK={s['BLOCK']} "
                      f"DEAD={s['DEAD']} OTHER={s['OTHER']} XRAY_FAIL={s['XRAY_FAIL']} | "
                      f"{time.time() - start_ts:.0f}с\n")

    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as ex:
        futures = {}
        it = iter(enumerate(alive, 1))

        for _ in range(NUM_WORKERS * 2):
            try:
                idx, v = next(it)
                futures[ex.submit(_run, (idx, v))] = idx
            except StopIteration:
                break

        while futures:
            done_futs = []
            for f in as_completed(list(futures.keys()), timeout=None):
                done_futs.append(f)
                break
            for f in done_futs:
                futures.pop(f, None)
                if STOP_FLAG:
                    break
                try:
                    idx, v = next(it)
                    futures[ex.submit(_run, (idx, v))] = idx
                except StopIteration:
                    pass
            if STOP_FLAG:
                break

    print("\n" + "═" * 60)
    print("ИТОГИ BUILD")
    print("═" * 60)
    for k, n in STATS.items():
        print(f"  {k:10s}: {n}")
    print(f"\nРабочих: {len(WINNERS)}")
    print(f"Время:  {(time.time() - start_ts) / 60:.1f} мин")

    Path(TEST_LOG_FILE).write_text("\n".join(LOG_LINES))
    with TESTED_LOCK:
        _save_tested_unsafe()

    if WINNERS:
        with WINNERS_LOCK:
            save_working_incremental(WINNERS)
        print(f"💾 Сохранено: {len(WINNERS)} рабочих")
        print("   Топ-5 по стабильности:")
        for w in WINNERS[:5]:
            print(f"   ★ {w.get('stability', 0)}/3  [{w['type']}] {w['name'] or w['host']}")
    else:
        print("❌ Рабочих не найдено")
        existing = load_working()
        if existing:
            print(f"   (оставляю ранее найденные: {len(existing)})")
        elif alive:
            with WINNERS_LOCK:
                _save_working_unsafe(alive[:5])
            print(f"   (сохранил {min(5, len(alive))} fallback)")


def mode_pick():
    idx, servers = _pick_next_available(0)
    if idx is None:
        print("❌ нет серверов вообще")
        sys.exit(1)
    v = servers[idx]
    activate_server(v)
    save_current_idx(idx)
    print(f"🎯 Активирован #{idx}: [{v['type']}] {v['name'] or v['host']}")
    print(f"   host={v['host']} port={v['port']} "
          f"stability={v.get('stability', '?')} "
          f"ban_count={v.get('ban_count', 0)}")


def mode_next():
    servers = load_working()
    if not servers:
        print("❌ список пуст")
        sys.exit(1)

    cur = load_current_idx()
    if cur < len(servers):
        mark_banned(servers[cur])

    idx, servers = _pick_next_available(cur + 1)
    if idx is None:
        print("❌ нет доступных серверов")
        sys.exit(1)

    v = servers[idx]
    activate_server(v)
    save_current_idx(idx)
    print(f"🔄 Переключено на #{idx}: [{v['type']}] {v['name'] or v['host']}")
    print(f"   stability={v.get('stability', '?')} "
          f"ban_count={v.get('ban_count', 0)}")


def mode_ban_current():
    servers = load_working()
    if not servers:
        sys.exit(0)
    cur = load_current_idx()
    if cur < len(servers):
        mark_banned(servers[cur])


def mode_stats():
    tested = load_tested()
    servers = load_working()
    now = time.time()

    available, cooldown = [], []
    for s in servers:
        if is_server_available(s, now):
            available.append(s)
        else:
            cooldown.append(s)

    print(f"Тестировано:      {len(tested)}")
    print(f"Рабочих всего:    {len(servers)}")
    print(f"  ✅ доступно:    {len(available)}")
    print(f"  ❄️ в cooldown:  {len(cooldown)}")

    if available:
        print("\nДоступные:")
        for s in available[:20]:
            ban_info = ""
            if s.get("ban_count", 0) > 0:
                ban_info = f" (было банов: {s['ban_count']})"
            print(f"  ★ {s.get('stability', '?')}/3  "
                  f"[{s['type']}] {s['name'] or s['host']}{ban_info}")

    if cooldown:
        print("\nВ cooldown (когда разблокируются):")
        for s in cooldown[:10]:
            banned_at = s.get("banned_at", 0)
            cd = _get_cooldown_for(s)
            left = max(0, (banned_at + cd) - now)
            print(f"  ❄️ {int(left // 60)} мин  "
                  f"[{s['type']}] {s['name'] or s['host']}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "pick"
    modes = {
        "build":       mode_build,
        "pick":        mode_pick,
        "next":        mode_next,
        "stats":       mode_stats,
        "ban-current": mode_ban_current,
    }
    if mode not in modes:
        print(f"Usage: {sys.argv[0]} [build|pick|next|stats|ban-current]")
        sys.exit(1)
    modes[mode]()
