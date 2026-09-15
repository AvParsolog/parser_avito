#!/usr/bin/env python3
"""
Пикер VLESS/VMess/Trojan серверов для Avito.
Режимы:
  python pick_vless.py build   → протестировать все источники, записать рабочие
  python pick_vless.py pick    → выбрать один рабочий сервер (из already built)
  python pick_vless.py next    → переключиться на следующий рабочий сервер
"""
import sys
import json
import time
import socket
import random
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

# ─── Источники (только VLESS/VMess/Trojan) ───
SOURCES = [
    # zieng2
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    # clean
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/trojan.txt",
    # ru-sni
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/trojan.txt",
    # ru-sni-local
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/vmess.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/trojan.txt",
]

# ─── Пути ───
XRAY_BIN         = "xray_bin/xray"
XRAY_CONFIG      = "data/xray_config.json"
XRAY_LOG         = "data/xray_test.log"
PROXY_PORT       = 1080
WORKING_FILE     = "data/working_servers.json"   # список рабочих (JSON)
CURRENT_IDX_FILE = "data/current_server_idx"     # индекс текущего рабочего
TEST_LOG_FILE    = "data/test_log.txt"

# ─── Тайминги ───
TCP_TIMEOUT  = 3
XRAY_WAIT    = 4
HTTP_TIMEOUT = 15

# ─── Тестовый URL Avito ───
TEST_URL = (
    "https://www.avito.ru/web/1/js/items"
    "?categoryId=6&localPriority=0&locationId=637640"
    "&presentationType=serp&query=mac+mini+m4&sort=default&page=1"
)

# ─── RU-маркеры ───
RU_TAGS = ["ru", "russia", "россия", "🇷🇺", "russian", "msk", "moscow",
           "спб", "saint", "petersburg", "novosibirsk", "ekaterinburg"]


# ═══════════════════════════════════════════════════════
#  ЗАГРУЗКА И ПАРСИНГ
# ═══════════════════════════════════════════════════════
def fetch_list(url: str) -> list[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "ignore").splitlines()
    except Exception as e:
        print(f"  ⚠️ Не удалось скачать {url}: {e}")
        return []


def parse_vless(url: str):
    if not url.startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(u.query))
        return {
            "type": "vless",
            "uuid": urllib.parse.unquote(u.username or ""),
            "host": u.hostname,
            "port": u.port,
            "params": params,
            "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
            "raw": url,
        }
    except Exception:
        return None


def parse_vmess(url: str):
    """VMess в base64 JSON."""
    import base64
    if not url.startswith("vmess://"):
        return None
    try:
        b64 = url[len("vmess://"):]
        # padding
        b64 += "=" * (-len(b64) % 4)
        decoded = base64.b64decode(b64).decode("utf-8")
        data = json.loads(decoded)
        return {
            "type": "vmess",
            "uuid": data.get("id", ""),
            "host": data.get("add", ""),
            "port": int(data.get("port", 0)),
            "params": {
                "security": "tls" if data.get("tls") == "tls" else "none",
                "type": data.get("net", "tcp"),
                "path": data.get("path", "/"),
                "host": data.get("host", ""),
                "sni": data.get("sni", data.get("host", "")),
                "fp": "chrome",
            },
            "name": data.get("ps", ""),
            "raw": url,
        }
    except Exception:
        return None


def parse_trojan(url: str):
    if not url.startswith("trojan://"):
        return None
    try:
        u = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(u.query))
        return {
            "type": "trojan",
            "password": urllib.parse.unquote(u.username or ""),
            "host": u.hostname,
            "port": u.port,
            "params": params,
            "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
            "raw": url,
        }
    except Exception:
        return None


def parse_any(url: str):
    for fn in (parse_vless, parse_vmess, parse_trojan):
        v = fn(url)
        if v:
            return v
    return None


def is_usable(v) -> bool:
    if not v or not v.get("host") or not v.get("port"):
        return False
    p = v.get("params", {})
    sec = p.get("security", "none")
    net = p.get("type", "tcp")
    if sec == "reality" and not p.get("pbk"):
        return False
    if net == "grpc" and not p.get("serviceName"):
        return False
    return True


# ═══════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ XRAY-КОНФИГА
# ═══════════════════════════════════════════════════════
def build_xray_config(v) -> dict:
    t = v["type"]
    p = v.get("params", {})
    net = p.get("type", "tcp")
    security = p.get("security", "none")

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

    if security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": p.get("sni", v["host"]),
            "fingerprint": p.get("fp", "chrome"),
            "allowInsecure": p.get("allowInsecure", "0") == "1",
        }
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
        }

    # ─── Outbound ───
    if t == "vless":
        outbound = {
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
        outbound = {
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
        outbound = {
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
        raise ValueError(f"Неизвестный тип: {t}")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": PROXY_PORT,
            "protocol": "http",
            "settings": {"timeout": 0},
        }],
        "outbounds": [outbound],
    }


# ═══════════════════════════════════════════════════════
#  TCP PING / XRAY START / TEST
# ═══════════════════════════════════════════════════════
def tcp_ping(host, port, timeout=TCP_TIMEOUT) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def start_xray(v) -> subprocess.Popen | None:
    cfg = build_xray_config(v)
    Path(XRAY_CONFIG).write_text(json.dumps(cfg, indent=2))
    with open(XRAY_LOG, "w") as log:
        proc = subprocess.Popen(
            [XRAY_BIN, "-c", XRAY_CONFIG],
            stdout=log, stderr=log,
        )
    for _ in range(XRAY_WAIT * 4):
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=1)
            s.close()
            time.sleep(0.5)
            return proc
        except Exception:
            time.sleep(0.25)
    proc.terminate()
    return None


def stop_xray(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def test_avito_via_proxy() -> tuple[str, str]:
    """Возвращает (verdict, info)."""
    cmd = [
        "curl", "-sS", "--max-time", str(HTTP_TIMEOUT),
        "-x", f"http://127.0.0.1:{PROXY_PORT}",
        "-H", "Accept: application/json, text/plain, */*",
        "-H", "Referer: https://www.avito.ru/",
        "-H", "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
        "-w", "\n__HTTP_CODE__%{http_code}",
        TEST_URL,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTP_TIMEOUT + 5)
        out = res.stdout
        code = ""
        if "__HTTP_CODE__" in out:
            body, _, code = out.rpartition("__HTTP_CODE__")
        else:
            body = out

        body_stripped = body.strip()

        if code == "200" and body_stripped.startswith(("{", "[")):
            return "OK", f"HTTP 200, JSON len={len(body_stripped)}"
        if "Доступ ограничен" in body or "проблема с IP" in body:
            return "IP_BAN", f"HTTP {code}, firewall page"
        if code in ("403", "429", "439"):
            return "BLOCK", f"HTTP {code}"
        if code in ("000", ""):
            return "DEAD", "no response"
        return "OTHER", f"HTTP {code}, body[:80]={body_stripped[:80]!r}"
    except subprocess.TimeoutExpired:
        return "DEAD", "timeout"
    except Exception as e:
        return "ERROR", str(e)


# ═══════════════════════════════════════════════════════
#  ЗАГРУЗКА ВСЕХ СЕРВЕРОВ
# ═══════════════════════════════════════════════════════
def load_all_servers() -> list[dict]:
    seen = set()
    servers = []
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


# ═══════════════════════════════════════════════════════
#  РЕЖИМЫ
# ═══════════════════════════════════════════════════════
def save_working(servers: list[dict]):
    Path(WORKING_FILE).write_text(json.dumps(servers, indent=2))
    Path(CURRENT_IDX_FILE).write_text("0")


def load_working() -> list[dict]:
    if not Path(WORKING_FILE).exists():
        return []
    try:
        return json.loads(Path(WORKING_FILE).read_text())
    except Exception:
        return []


def load_current_idx() -> int:
    if not Path(CURRENT_IDX_FILE).exists():
        return 0
    try:
        return int(Path(CURRENT_IDX_FILE).read_text().strip() or "0")
    except Exception:
        return 0


def save_current_idx(idx: int):
    Path(CURRENT_IDX_FILE).write_text(str(idx))


def activate_server(v: dict):
    """Записать xray_config.json для конкретного сервера."""
    cfg = build_xray_config(v)
    Path(XRAY_CONFIG).write_text(json.dumps(cfg, indent=2))


def mode_build():
    """Протестировать все источники, записать рабочие."""
    servers = load_all_servers()
    print(f"   всего пригодных серверов: {len(servers)}")

    ru = [s for s in servers if any(t in (s["name"] or "").lower() for t in RU_TAGS)]
    pool = ru if ru else servers
    print(f"   в пуле (RU-приоритет): {len(pool)}")

    winners = []
    stats = {"OK": 0, "IP_BAN": 0, "BLOCK": 0, "DEAD": 0, "OTHER": 0, "ERROR": 0}
    log_lines = []

    for i, v in enumerate(pool, 1):
        name = (v["name"] or v["host"])[:50]
        print(f"\n[{i}/{len(pool)}] [{v['type']}] {v['host']}:{v['port']} — {name}")

        if not tcp_ping(v["host"], v["port"]):
            stats["DEAD"] += 1
            print(f"   ❌ TCP ping fail")
            log_lines.append(f"[{i}] DEAD {v['type']} {v['host']}:{v['port']} {name}")
            continue

        proc = start_xray(v)
        if not proc:
            stats["DEAD"] += 1
            print(f"   ❌ Xray не поднялся")
            log_lines.append(f"[{i}] XRAY_FAIL {v['type']} {v['host']}:{v['port']} {name}")
            continue

        verdict, info = test_avito_via_proxy()
        stop_xray(proc)
        stats[verdict] = stats.get(verdict, 0) + 1
        print(f"   → {verdict}: {info}")
        log_lines.append(f"[{i}] {verdict} {v['type']} {v['host']}:{v['port']} {name} | {info}")

        if verdict == "OK":
            winners.append(v)
            print(f"   ⭐ РАБОЧИЙ!")

    print("\n" + "═" * 60)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("═" * 60)
    for k, n in stats.items():
        print(f"  {k:8s}: {n}")
    print(f"\nРабочих серверов: {len(winners)}")

    Path(TEST_LOG_FILE).write_text("\n".join(log_lines))
    save_working(winners)

    if winners:
        print(f"\n💾 Сохранено в {WORKING_FILE}")
        for w in winners:
            print(f"  ✅ [{w['type']}] {w['name'] or w['host']}")
    else:
        print("\n❌ Ни один сервер не прошёл проверку Avito")
        sys.exit(1)


def mode_pick():
    """Выбрать текущий рабочий сервер из already built."""
    servers = load_working()
    if not servers:
        print("❌ Список рабочих пуст — сначала запустите build")
        sys.exit(1)
    idx = load_current_idx() % len(servers)
    v = servers[idx]
    activate_server(v)
    print(f"🎯 Активирован сервер #{idx}: [{v['type']}] {v['name'] or v['host']}")
    print(f"   host={v['host']} port={v['port']}")


def mode_next():
    """Переключиться на следующий рабочий."""
    servers = load_working()
    if not servers:
        print("❌ Список рабочих пуст")
        sys.exit(1)
    idx = (load_current_idx() + 1) % len(servers)
    save_current_idx(idx)
    v = servers[idx]
    activate_server(v)
    print(f"🔄 Переключено на сервер #{idx}: [{v['type']}] {v['name'] or v['host']}")
    print(f"   host={v['host']} port={v['port']}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "pick"
    if mode == "build":
        mode_build()
    elif mode == "pick":
        mode_pick()
    elif mode == "next":
        mode_next()
    else:
        print(f"Usage: {sys.argv[0]} [build|pick|next]")
        sys.exit(1)
