#!/usr/bin/env python3
"""
Высокопараллельный пикер VLESS/VMess/Trojan для Avito (v4).

Особенности:
  • Параллельный TCP-ping (400 потоков)
  • Пул из N Xray-инстансов на портах 10800.. (60 по умолчанию)
  • Инкрементальное сохранение рабочих серверов (parser читает на лету)
  • Периодический flush tested_set + обработка SIGTERM
  • Работает на AMD64 и ARM64 (Xray скачивается в workflow, не тут)
"""
import os
import sys
import json
import time
import socket
import random
import signal
import hashlib
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from threading import Lock
from pathlib import Path

# ══════════════════════════════════════════════════════════════
#  НАСТРОЙКИ
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

# ─── Пути ───
XRAY_BIN         = "xray_bin/xray"
WORKING_FILE     = "data/working_servers.json"
TESTED_FILE      = "data/tested_servers.txt"
CURRENT_IDX_FILE = "data/current_server_idx"
TEST_LOG_FILE    = "data/test_log.txt"
TMP_DIR          = Path("data/tmp_xray")
XRAY_CONFIG      = "data/xray_config.json"

# ─── Параллельность ───
NUM_WORKERS      = 60          # параллельных Xray-инстансов
TCP_THREADS      = 400         # потоков на TCP-ping
PORT_BASE        = 10800       # 10800..10859

# ─── Тайминги ───
TCP_TIMEOUT         = 2
XRAY_WAIT           = 3
HTTP_TIMEOUT        = 8
BUILD_TIME_BUDGET   = 999_999_999   # практически без лимита — идём до конца
FLUSH_TESTED_EVERY  = 60            # сек между сохранениями tested_set

# ─── Цели ───
MAX_WINNERS = 999_999               # не останавливаемся, пока есть серверы


# ─── Тестовый URL Avito ───
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
    if not url.startswith("vless://"): return None
    try:
        u = urllib.parse.urlparse(url)
        p = dict(urllib.parse.parse_qsl(u.query))
        return {"type": "vless", "uuid": urllib.parse.unquote(u.username or ""),
                "host": u.hostname, "port": u.port, "params": p,
                "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
                "raw": url}
    except Exception:
        return None


def parse_vmess(url):
    import base64
    if not url.startswith("vmess://"): return None
    try:
        b64 = url[8:]
        b64 += "=" * (-len(b64) % 4)
        d = json.loads(base64.b64decode(b64).decode("utf-8"))
        return {"type": "vmess", "uuid": d.get("id", ""),
                "host": d.get("add", ""), "port": int(d.get("port", 0)),
                "params": {"security": "tls" if d.get("tls") == "tls" else "none",
                           "type": d.get("net", "tcp"), "path": d.get("path", "/"),
                           "host": d.get("host", ""),
                           "sni": d.get("sni", d.get("host", "")),
                           "fp": "chrome"},
                "name": d.get("ps", ""), "raw": url}
    except Exception:
        return None


def parse_trojan(url):
    if not url.startswith("trojan://"): return None
    try:
        u = urllib.parse.urlparse(url)
        p = dict(urllib.parse.parse_qsl(u.query))
        return {"type": "trojan", "password": urllib.parse.unquote(u.username or ""),
                "host": u.hostname, "port": u.port, "params": p,
                "name": urllib.parse.unquote(u.fragment) if u.fragment else "",
                "raw": url}
    except Exception:
        return None


def parse_any(url):
    for fn in (parse_vless, parse_vmess, parse_trojan):
        v = fn(url)
        if v: return v
    return None


def is_usable(v):
    if not v or not v.get("host") or not v.get("port"): return False
    p = v.get("params", {})
    if p.get("security", "none") == "reality" and not p.get("pbk"): return False
    if p.get("type", "tcp") == "grpc" and not p.get("serviceName"): return False
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
        stream["wsSettings"] = {"path": p.get("path", "/"),
                                "headers": {"Host": p.get("host", v["host"])}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    elif net == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {"header": {"type": "http",
            "request": {"path": [p.get("path", "/")],
                        "headers": {"Host": [p.get("host", v["host"])]}}}}

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
        out = {"protocol": "vless",
               "settings": {"vnext": [{"address": v["host"], "port": int(v["port"]),
                    "users": [{"id": v["uuid"], "encryption": "none",
                               "flow": p.get("flow", "")}]}]},
               "streamSettings": stream}
    elif t == "vmess":
        out = {"protocol": "vmess",
               "settings": {"vnext": [{"address": v["host"], "port": int(v["port"]),
                    "users": [{"id": v["uuid"], "alterId": 0,
                               "security": "auto"}]}]},
               "streamSettings": stream}
    elif t == "trojan":
        out = {"protocol": "trojan",
               "settings": {"servers": [{"address": v["host"],
                    "port": int(v["port"]), "password": v["password"]}]},
               "streamSettings": stream}
    else:
        raise ValueError(f"Unknown type: {t}")

    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": port,
                          "protocol": "http", "settings": {"timeout": 0}}],
            "outbounds": [out]}


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
            if ok: alive.append(v)
            if done % 1000 == 0 or done == total:
                print(f"   [{done}/{total}] живых: {len(alive)}")
    return alive


# ══════════════════════════════════════════════════════════════
#  XRAY WORKER
# ══════════════════════════════════════════════════════════════
def start_xray(v, port, cfg_path, log_path):
    Path(cfg_path).write_text(json.dumps(build_xray_config(v, port), indent=2))
    with open(log_path, "w") as log:
        proc = subprocess.Popen([XRAY_BIN, "-c", cfg_path],
                                stdout=log, stderr=log)
    # Ждём порт
    for _ in range(XRAY_WAIT * 5):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            time.sleep(0.2)
            return proc
        except Exception:
            time.sleep(0.2)
    try:
        proc.terminate(); proc.wait(timeout=2)
    except Exception:
        try: proc.kill()
        except Exception: pass
    return None


def stop_xray(proc):
    if not proc: return
    try:
        proc.terminate(); proc.wait(timeout=2)
    except Exception:
        try: proc.kill()
        except Exception: pass


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
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=HTTP_TIMEOUT + 3)
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
    """Берёт порт из пула, поднимает Xray, тестирует, убирает."""
    try:
        port = PORT_POOL.get(timeout=120)
    except Empty:
        return "ERROR", "no free port", -1

    try:
        cfg_path = TMP_DIR / f"cfg_{port}.json"
        log_path = TMP_DIR / f"log_{port}.log"

        proc = start_xray(v, port, cfg_path, log_path)
        if not proc:
            tail = read_log_tail(log_path)
            return "XRAY_FAIL", f"xray fail | {tail}", port

        try:
            verdict, info = curl_avito_via_port(port)
            return verdict, info, port
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
#  ХРАНИЛИЩА (атомарные)
# ══════════════════════════════════════════════════════════════
def _save_tested_unsafe():
    tmp = Path(str(TESTED_FILE) + ".tmp")
    tmp.write_text("\n".join(sorted(TESTED_SET)))
    tmp.replace(TESTED_FILE)


def _save_working_unsafe(servers):
    tmp = Path(str(WORKING_FILE) + ".tmp")
    tmp.write_text(json.dumps(servers, indent=2))
    tmp.replace(WORKING_FILE)
    Path(CURRENT_IDX_FILE).write_text("0")


def save_working_incremental(servers):
    """Публичная обёртка для вызова из worker (уже под WINNERS_LOCK)."""
    _save_working_unsafe(servers)


def load_tested():
    if not Path(TESTED_FILE).exists(): return set()
    return set(Path(TESTED_FILE).read_text().splitlines())


def load_working():
    if not Path(WORKING_FILE).exists(): return []
    try:
        return json.loads(Path(WORKING_FILE).read_text())
    except Exception:
        return []


def load_current_idx():
    if not Path(CURRENT_IDX_FILE).exists(): return 0
    try:
        return int(Path(CURRENT_IDX_FILE).read_text().strip() or "0")
    except Exception:
        return 0


def save_current_idx(idx): Path(CURRENT_IDX_FILE).write_text(str(idx))


def activate_server(v):
    """Собираем основной xray_config.json на порту 1080."""
    Path(XRAY_CONFIG).write_text(json.dumps(build_xray_config(v, 1080), indent=2))


def load_all_servers():
    seen, servers = set(), []
    for src in SOURCES:
        print(f"📥 {src}")
        for line in fetch_list(src):
            line = line.strip()
            if not line or line in seen: continue
            seen.add(line)
            v = parse_any(line)
            if is_usable(v): servers.append(v)
    return servers


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
    if STOP_FLAG: return

    name = (v["name"] or v["host"])[:50]
    verdict, info, port = test_one_server(v)

    with TESTED_LOCK:
        TESTED_SET.add(server_hash(v))

    with STATS_LOCK:
        STATS[verdict] = STATS.get(verdict, 0) + 1

    with LOG_LOCK:
        LOG_LINES.append(
            f"[{idx}] {verdict} {v['type']} {v['host']}:{v['port']} {name} | {info}"
        )

    # Печатаем только интересное (не DEAD)
    if verdict not in ("DEAD",):
        print(f"[{idx}/{total}] {verdict}: [{v['type']}] {v['host']}:{v['port']} — {name}")
        if verdict in ("OK", "OTHER", "ERROR") and info:
            print(f"          → {info}")

    if verdict == "OK":
        with WINNERS_LOCK:
            WINNERS.append(v)
            save_working_incremental(WINNERS)
            print(f"   ⭐ РАБОЧИЙ! Всего: {len(WINNERS)} — записано в файл")
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

    # ─── TCP-ping ───
    alive = ping_all(fresh)
    print(f"   TCP-живых: {len(alive)}")
    if not alive:
        print("❌ ни один не отвечает на TCP")
        sys.exit(1)

    random.shuffle(alive)

    # ─── Avito-тест параллельно ───
    print(f"\n🧪 Avito-тест: {len(alive)} серверов, {NUM_WORKERS} параллельных Xray")
    print(f"   бюджет: {BUILD_TIME_BUDGET // 60} мин, цель: {MAX_WINNERS} рабочих\n")

    total = len(alive)
    done_count = [0]
    done_lock = Lock()
    last_progress = [time.time()]

    def _run(args):
        idx, v = args
        if STOP_FLAG: return
        if time.time() - start_ts > BUILD_TIME_BUDGET: return
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

    # Ограничиваем очередь задач, чтобы не держать 16k объектов в памяти
    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as ex:
        futures = {}
        it = iter(enumerate(alive, 1))
        # Первая партия
        for _ in range(NUM_WORKERS * 2):
            try:
                idx, v = next(it)
                futures[ex.submit(_run, (idx, v))] = idx
            except StopIteration:
                break
        # Подкидываем новые задачи по мере завершения
        while futures:
            done_futs = []
            for f in as_completed(list(futures.keys()), timeout=None):
                done_futs.append(f)
                break
            for f in done_futs:
                futures.pop(f, None)
                if STOP_FLAG or time.time() - start_ts > BUILD_TIME_BUDGET:
                    break
                try:
                    idx, v = next(it)
                    futures[ex.submit(_run, (idx, v))] = idx
                except StopIteration:
                    pass
            if STOP_FLAG or time.time() - start_ts > BUILD_TIME_BUDGET:
                break

    # ─── Итоги ───
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
    s = load_working()
    if not s:
        print("❌ список пуст")
        sys.exit(1)
    idx = load_current_idx() % len(s)
    activate_server(s[idx])
    print(f"🎯 Активирован #{idx}: [{s[idx]['type']}] {s[idx]['name'] or s[idx]['host']}")
    print(f"   host={s[idx]['host']} port={s[idx]['port']}")


def mode_next():
    s = load_working()
    if not s:
        print("❌ список пуст")
        sys.exit(1)
    idx = (load_current_idx() + 1) % len(s)
    save_current_idx(idx)
    activate_server(s[idx])
    print(f"🔄 Переключено на #{idx}: [{s[idx]['type']}] {s[idx]['name'] or s[idx]['host']}")


def mode_stats():
    tested = load_tested()
    working = load_working()
    print(f"Тестировано: {len(tested)}")
    print(f"Рабочих:     {len(working)}")
    for w in working:
        print(f"  ✅ [{w['type']}] {w['name'] or w['host']}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "pick"
    modes = {"build": mode_build, "pick": mode_pick,
             "next": mode_next, "stats": mode_stats}
    if mode not in modes:
        print(f"Usage: {sys.argv[0]} [build|pick|next|stats]")
        sys.exit(1)
    modes[mode]()
