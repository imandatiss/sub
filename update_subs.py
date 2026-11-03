#!/usr/bin/env python3
"""
جمع‌آوری کانفیگ از لینک‌های subscription منبع، تست واقعی با xray-core،
و ساخت فایل subscription از سرورهای سالم (مرتب‌شده بر اساس سرعت).
"""
import base64
import json
import os
import queue
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from urllib.parse import parse_qs, unquote, urlparse

import requests

XRAY = shutil.which("xray") or "./xray"
TEST_URL = os.getenv("TEST_URL", "https://www.gstatic.com/generate_204")
MAX_KEEP = int(os.getenv("MAX_KEEP", 60))     # حداکثر تعداد سرور در خروجی
MAX_TEST = int(os.getenv("MAX_TEST", 1500))    # حداکثر تعداد سرور برای تست
WORKERS = int(os.getenv("WORKERS", 20))        # تعداد تست همزمان
TIMEOUT = int(os.getenv("TIMEOUT", 8))         # ثانیه
BASE_PORT = 21000
SPEED_URL = os.getenv("SPEED_URL", "https://speed.cloudflare.com/__down?bytes=5000000")
SPEED_TIME = int(os.getenv("SPEED_TIME", 10))      # حداکثر ثانیه دانلود برای هر سرور
DEEP_N = int(os.getenv("DEEP_N", 300))             # چند سرور سریع‌تر وارد تست سرعت شوند
DEEP_WORKERS = int(os.getenv("DEEP_WORKERS", 5))   # تست سرعت همزمان (کم، تا پهنای باند تقسیم نشود)
MIN_KBPS = int(os.getenv("MIN_KBPS", 500))         # حداقل سرعت قابل قبول (کیلوبایت بر ثانیه)


# ---------- ابزارهای کمکی ----------
def b64d(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def fetch(url: str):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "v2rayN/6.0"})
        text = r.text.strip()
        if "://" not in text[:60]:
            text = b64d(text)
        return re.findall(r'(?:vmess|vless|trojan|ss)://[^\s<>"\']+', text)
    except Exception as e:
        print(f"[!] خطا در دریافت {url}: {e}")
        return []


# ---------- تبدیل لینک به outbound ----------
def stream_settings(q: dict, sec: str) -> dict:
    net = q.get("type") or "tcp"
    if net not in ("tcp", "ws", "grpc"):
        raise ValueError(f"transport پشتیبانی نمی‌شود: {net}")
    s = {"network": net, "security": sec if sec in ("tls", "reality") else "none"}
    if sec == "tls":
        tls = {"serverName": q.get("sni") or q.get("host") or "",
               "fingerprint": q.get("fp") or "chrome"}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        s["tlsSettings"] = tls
    elif sec == "reality":
        s["realitySettings"] = {
            "serverName": q.get("sni", ""), "fingerprint": q.get("fp") or "chrome",
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    if net == "ws":
        s["wsSettings"] = {"path": q.get("path", "/"),
                           "headers": {"Host": q.get("host", "")}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif net == "tcp" and q.get("headerType") == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [q.get("path", "/")], "headers": {"Host": [q.get("host", "")]}}}}
    return s


def to_outbound(link: str) -> dict:
    scheme = link.split("://")[0]

    if scheme == "vmess":
        d = json.loads(b64d(link[8:]))
        q = {"type": d.get("net", "tcp"), "sni": d.get("sni") or d.get("host"),
             "host": d.get("host"), "path": d.get("path"), "alpn": d.get("alpn"),
             "fp": d.get("fp"), "serviceName": d.get("path"),
             "headerType": d.get("type")}
        q = {k: v for k, v in q.items() if v}
        sec = "tls" if d.get("tls") == "tls" else "none"
        return {"protocol": "vmess", "settings": {"vnext": [{
            "address": d["add"], "port": int(d["port"]),
            "users": [{"id": d["id"], "alterId": int(d.get("aid", 0) or 0),
                       "security": d.get("scy", "auto")}]}]},
            "streamSettings": stream_settings(q, sec)}

    if scheme in ("vless", "trojan"):
        u = urlparse(link)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if scheme == "vless":
            sec = q.get("security", "none")
            return {"protocol": "vless", "settings": {"vnext": [{
                "address": u.hostname, "port": u.port,
                "users": [{"id": u.username, "encryption": q.get("encryption", "none"),
                           "flow": q.get("flow", "")}]}]},
                "streamSettings": stream_settings(q, sec)}
        sec = q.get("security", "tls")
        return {"protocol": "trojan", "settings": {"servers": [{
            "address": u.hostname, "port": u.port,
            "password": unquote(u.username)}]},
            "streamSettings": stream_settings(q, sec)}

    if scheme == "ss":
        body = link[5:].split("#")[0]
        if "plugin=" in body:
            raise ValueError("plugin پشتیبانی نمی‌شود")
        body = body.split("?")[0].rstrip("/")
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                method, pw = b64d(userinfo).split(":", 1)
            except Exception:
                method, pw = unquote(userinfo).split(":", 1)
        else:
            userinfo, hostport = b64d(body).rsplit("@", 1)
            method, pw = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {"protocol": "shadowsocks", "settings": {"servers": [{
            "address": host.strip("[]"), "port": int(port),
            "method": method, "password": pw}]}}

    raise ValueError("پروتکل ناشناخته")


# ---------- تست ----------
ports = queue.Queue()
for i in range(WORKERS):
    ports.put(BASE_PORT + i)


def wait_port(port, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


@contextmanager
def proxy_for(link: str):
    """xray را برای این لینک بالا می‌آورد و پورت socks را می‌دهد (یا None)."""
    ob = to_outbound(link)
    port = ports.get()
    cfg_path = None
    proc = None
    try:
        cfg = {"log": {"loglevel": "none"},
               "inbounds": [{"listen": "127.0.0.1", "port": port,
                             "protocol": "socks", "settings": {"udp": False}}],
               "outbounds": [ob]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            cfg_path = f.name
        proc = subprocess.Popen([XRAY, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        yield port if wait_port(port) else None
    finally:
        if proc:
            proc.kill()
            proc.wait()
        if cfg_path and os.path.exists(cfg_path):
            os.unlink(cfg_path)
        ports.put(port)


def curl(port, url, max_time):
    r = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total} %{speed_download}",
         "-x", f"socks5h://127.0.0.1:{port}", "--max-time", str(max_time), url],
        capture_output=True, text=True)
    parts = r.stdout.split()
    if len(parts) != 3:
        return None
    return parts[0], float(parts[1]), float(parts[2])


def quick(link: str):
    """مرحله ۱: فقط وصل می‌شود یا نه."""
    try:
        with proxy_for(link) as port:
            if port:
                r = curl(port, TEST_URL, TIMEOUT)
                if r and r[0] in ("204", "200"):
                    return link, int(r[1] * 1000)
    except Exception:
        pass
    return None


def deep(item):
    """مرحله ۲: پایداری (۳ پینگ پشت‌سرهم) و سرعت دانلود."""
    link = item[0]
    try:
        with proxy_for(link) as port:
            if not port:
                return None
            lat = []
            for _ in range(3):
                r = curl(port, TEST_URL, 5)
                if not r or r[0] not in ("204", "200"):
                    return None
                lat.append(r[1] * 1000)
            r = curl(port, SPEED_URL, SPEED_TIME)
            if not r or r[0] != "200":
                return None
            return link, int(sum(lat) / 3), int(max(lat) - min(lat)), r[2] / 1024
    except Exception:
        return None


def rename(link: str, name: str) -> str:
    if link.startswith("vmess://"):
        d = json.loads(b64d(link[8:]))
        d["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(d).encode()).decode()
    return link.split("#")[0] + "#" + name


# ---------- اجرا ----------
def main():
    with open("sources.txt", encoding="utf-8") as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    links = {}
    for url in sources:
        found = fetch(url)
        print(f"[+] {len(found)} کانفیگ از {url}")
        for l in found:
            links.setdefault(l.split("#")[0], l)
    links = list(links.values())
    random.shuffle(links)
    links = links[:MAX_TEST]
    print(f"[*] تست {len(links)} کانفیگ یکتا ...")

    with ThreadPoolExecutor(WORKERS) as ex:
        alive = [r for r in ex.map(quick, links) if r]
    alive.sort(key=lambda x: x[1])
    print(f"[✓] مرحله ۱: {len(alive)} سرور وصل می‌شود")

    candidates = alive[:DEEP_N]
    print(f"[*] مرحله ۲: تست سرعت و پایداری {len(candidates)} سرور ...")
    with ThreadPoolExecutor(DEEP_WORKERS) as ex:
        deep_res = [r for r in ex.map(deep, candidates) if r]
    deep_res.sort(key=lambda x: x[3], reverse=True)   # بر اساس سرعت

    good = [r for r in deep_res if r[3] >= MIN_KBPS]
    if not good and deep_res:
        print("[!] هیچ سروری به حداقل سرعت نرسید؛ بهترین‌های موجود نگه داشته شد.")
        good = deep_res[:20]
    good = good[:MAX_KEEP]
    print(f"[✓] {len(good)} سرور سریع و پایدار")

    if not good:
        print("[!] هیچ سرور سالمی پیدا نشد؛ فایل قبلی دست‌نخورده ماند.")
        return

    out = []
    for i, (l, ms, jitter, kbps) in enumerate(good):
        mbps = kbps * 8 / 1024
        out.append(rename(l, f"{i+1:03d}-{mbps:.1f}Mbps-{ms}ms"))
    with open("sub_raw.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(out).encode()).decode())


if __name__ == "__main__":
    main()
