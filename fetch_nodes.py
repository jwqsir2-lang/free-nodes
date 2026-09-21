#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动搜集 / 检测 / 生成订阅
--------------------------------------------------
流程：拉取 GitHub 上的公开节点源 -> 解析成统一节点格式 -> 去重
      -> 剔除非公网地址与假节点 -> 并发存活检测 -> 排序
      -> 输出 Clash 订阅 / v2ray 订阅 / HTTP 专用列表 / 订阅页
输出目录：dist/
"""
import base64
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

import yaml

OUT_DIR = os.environ.get("OUT_DIR", "dist")

# ---------------------------------------------------------------- 节点源
# fmt: auto | base64 | clash | plain | iplist
SOURCES = [
    {"name": "anaer/Sub",            "url": "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",                                     "fmt": "clash"},
    {"name": "ermaozi/get_subscribe","url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",              "fmt": "auto"},
    {"name": "peasoft/NoMoreWalls",  "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",                          "fmt": "auto"},
    {"name": "mahdibland/Eternity",  "url": "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",            "fmt": "auto"},
    {"name": "freefq/free",          "url": "https://raw.githubusercontent.com/freefq/free/master/v2",                                       "fmt": "auto"},
    {"name": "Pawdroid/Free-servers","url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",                               "fmt": "auto"},
    {"name": "ripaojiedian/freenode","url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",                               "fmt": "auto"},
    {"name": "Barabama/FreeNodes",   "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt",                   "fmt": "auto"},
    # 纯 HTTP/HTTPS/SOCKS 代理（ip:port 列表）
    {"name": "proxifly/http",        "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt","fmt": "iplist"},
    {"name": "TheSpeedX/http",       "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",                         "fmt": "iplist"},
    {"name": "monosans/http",        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",                    "fmt": "iplist"},
    # HTTPS 代理列表（其中大量是 443 端口的 TLS 代理）
    {"name": "zloi-user/https",      "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",                           "fmt": "iplist", "tls_hint": True},
    {"name": "proxifly/https",       "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt","fmt": "iplist", "tls_hint": True},
    {"name": "r00tee/Https",         "url": "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",                             "fmt": "iplist", "tls_hint": True},
    {"name": "jetkai/https",         "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",  "fmt": "iplist", "tls_hint": True},
    {"name": "clarketm/raw",         "url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",                "fmt": "iplist", "tls_hint": True},
    {"name": "roosterkid/HTTPS",     "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",                  "fmt": "iplist", "tls_hint": True},
    {"name": "ShiftyTR/https",       "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",                          "fmt": "iplist", "tls_hint": True},
]

MAX_PER_SOURCE = int(os.environ.get("MAX_PER_SOURCE", "6000"))
MAX_TOTAL_TEST = int(os.environ.get("MAX_TOTAL_TEST", "9000"))
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "3"))
HTTP_FUNC_LIMIT = int(os.environ.get("HTTP_FUNC_LIMIT", "400"))   # 只对最快的 N 个 http 代理做功能测试
TEST_URLS = ["http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

BAD_NETS = [ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
)]
SUPPORTED = ("vmess", "vless", "trojan", "ss", "hysteria2", "hysteria", "http", "socks5", "tuic")


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- 取回
def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    opener = (urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
              if proxy else urllib.request.build_opener())
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def b64decode_any(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad).decode("utf-8", "ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------- 工具
def is_public_host(host):
    """非公网地址一律丢弃（NoMoreWalls 这类源里混了不少 127.0.0.x 假节点）"""
    host = (host or "").strip().strip("[]")
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", host))   # 域名
    if ip.version == 6:
        return not (ip.is_loopback or ip.is_private or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    return not any(ip in n for n in BAD_NETS)


def clean_name(raw, fallback):
    n = re.sub(r"[\x00-\x1f\x7f]+", " ", urllib.parse.unquote(raw or "")).strip()
    n = re.sub(r"\s+", " ", n)[:44]
    return n or fallback


def as_int(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def qs(query):
    return {k: v[0] for k, v in urllib.parse.parse_qs(query or "", keep_blank_values=True).items()}


# ---------------------------------------------------------------- 各类节点解析
def p_vmess(link, name_hint):
    body = link[8:].split("#")[0].strip()
    try:
        j = json.loads(b64decode_any(body))
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    server = str(j.get("add", "")).strip()
    port = as_int(j.get("port"), 0)
    uuid = str(j.get("id", "")).strip()
    if not (server and port and uuid):
        return None
    net = (str(j.get("net", "tcp")) or "tcp").lower()
    tls = str(j.get("tls", "")).lower() in ("tls", "true", "1")
    host = str(j.get("host", "")).strip()
    path = str(j.get("path", "")).strip()
    sni = str(j.get("sni", "")).strip()
    n = {
        "name": clean_name(j.get("ps"), name_hint), "type": "vmess", "server": server,
        "port": port, "uuid": uuid, "alterId": as_int(j.get("aid"), 0),
        "cipher": str(j.get("scy") or "auto").strip() or "auto",
        "udp": True, "network": net,
    }
    if tls:
        n["tls"] = True
        n["skip-cert-verify"] = True
        if sni or host:
            n["servername"] = sni or host
    if net == "ws":
        n["ws-opts"] = {"path": path or "/", **({"headers": {"Host": host}} if host else {})}
    elif net == "grpc":
        n["grpc-opts"] = {"grpc-service-name": path or ""}
    elif net == "h2":
        n["h2-opts"] = {"path": path or "/", **({"host": [host]} if host else {})}
    return n


def p_vless(link, name_hint):
    u = urllib.parse.urlsplit(link)
    q = qs(u.query)
    server, port, uuid = (u.hostname or ""), (u.port or 0), (u.username or "")
    if not (server and port and uuid):
        return None
    sec = (q.get("security") or "none").lower()
    net = (q.get("type") or "tcp").lower()
    n = {"name": clean_name(u.fragment, name_hint), "type": "vless", "server": server,
         "port": port, "uuid": uuid, "udp": True}
    flow = q.get("flow", "").strip()
    if sec in ("tls", "reality"):
        n["tls"] = True
        n["skip-cert-verify"] = True
        if q.get("sni") or q.get("host"):
            n["servername"] = q.get("sni") or q.get("host")
        if q.get("fp"):
            n["client-fingerprint"] = q["fp"]
        if q.get("alpn"):
            n["alpn"] = [a for a in q["alpn"].split(",") if a]
        if sec == "reality":
            ro = {}
            if q.get("pbk"):
                ro["public-key"] = q["pbk"]
            if q.get("sid"):
                ro["short-id"] = q["sid"]
            if ro:
                n["reality-opts"] = ro
    if net == "ws":
        n["network"] = "ws"
        n["ws-opts"] = {"path": q.get("path") or "/", **({"headers": {"Host": q["host"]}} if q.get("host") else {})}
    elif net == "grpc":
        n["network"] = "grpc"
        n["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or q.get("path") or ""}
    elif net == "tcp" and flow:
        n["flow"] = flow
    return n


def p_trojan(link, name_hint):
    u = urllib.parse.urlsplit(link)
    q = qs(u.query)
    server, port, pw = u.hostname, u.port, urllib.parse.unquote(u.username or "")
    if not (server and port and pw):
        return None
    n = {"name": clean_name(u.fragment, name_hint), "type": "trojan", "server": server, "port": port,
         "password": pw, "udp": True, "skip-cert-verify": True}
    if q.get("sni") or q.get("peer"):
        n["sni"] = q.get("sni") or q.get("peer")
    if q.get("fp"):
        n["client-fingerprint"] = q["fp"]
    net = (q.get("type") or "tcp").lower()
    if net == "ws":
        n["network"] = "ws"
        n["ws-opts"] = {"path": q.get("path") or "/", **({"headers": {"Host": q["host"]}} if q.get("host") else {})}
    elif net == "grpc":
        n["network"] = "grpc"
        n["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or ""}
    return n


def p_ss(link, name_hint):
    if "plugin=" in link:          # obfs / v2ray-plugin 之类的先不要，容易生成坏节点
        return None
    u = urllib.parse.urlsplit(link)
    userinfo, server, port = u.username, u.hostname, u.port
    if server and port and userinfo:
        if ":" in userinfo:
            method, pw = userinfo.split(":", 1)
        else:
            dec = b64decode_any(userinfo)
            if ":" not in dec:
                return None
            method, pw = dec.split(":", 1)
    else:                            # ss://base64(method:password@host:port)
        dec = b64decode_any(link[5:].split("#")[0].split("?")[0])
        m = re.match(r"^(.+?):(.+)@(.+):(\d+)$", dec)
        if not m:
            return None
        method, pw, server, port = m.group(1), m.group(2), m.group(3), as_int(m.group(4))
    if not (server and port and method and pw):
        return None
    return {"name": clean_name(u.fragment, name_hint), "type": "ss", "server": server, "port": port,
            "cipher": method.strip(), "password": pw, "udp": True}


def p_hysteria2(link, name_hint):
    u = urllib.parse.urlsplit(link)
    q = qs(u.query)
    server, port = u.hostname, u.port
    pw = urllib.parse.unquote(u.username or "") or q.get("password") or ""
    if not (server and port and pw):
        return None
    n = {"name": clean_name(u.fragment, name_hint), "type": "hysteria2", "server": server, "port": port,
         "password": pw, "udp": True}
    if q.get("sni"):
        n["sni"] = q["sni"]
    if str(q.get("insecure", "")).lower() in ("1", "true"):
        n["skip-cert-verify"] = True
    if q.get("obfs"):
        n["obfs"] = q["obfs"]
        if q.get("obfs-password"):
            n["obfs-password"] = q["obfs-password"]
    return n


def p_hysteria(link, name_hint):
    u = urllib.parse.urlsplit(link)
    q = qs(u.query)
    if not u.hostname or not u.port:
        return None
    n = {"name": clean_name(u.fragment, name_hint), "type": "hysteria", "server": u.hostname, "port": u.port,
         "udp": True}
    if q.get("auth"):
        n["auth-str"] = q["auth"]
    if q.get("upmbps"):
        n["up"] = q["upmbps"]
    if q.get("downmbps"):
        n["down"] = q["downmbps"]
    if q.get("peer") or q.get("sni"):
        n["sni"] = q.get("peer") or q.get("sni")
    if q.get("alpn"):
        n["alpn"] = [a for a in q["alpn"].split(",") if a]
    if str(q.get("insecure", "")).lower() in ("1", "true"):
        n["skip-cert-verify"] = True
    return n


def p_tuic(link, name_hint):
    u = urllib.parse.urlsplit(link)
    q = qs(u.query)
    if not (u.hostname and u.port):
        return None
    n = {"name": clean_name(u.fragment, name_hint), "type": "tuic", "server": u.hostname, "port": u.port,
         "udp": True, "skip-cert-verify": True}
    if u.username:
        n["uuid"] = urllib.parse.unquote(u.username)
    if u.password:
        n["password"] = urllib.parse.unquote(u.password)
    if q.get("sni"):
        n["sni"] = q["sni"]
    if q.get("alpn"):
        n["alpn"] = [a for a in q["alpn"].split(",") if a]
    if q.get("congestion_control"):
        n["congestion-controller"] = q["congestion_control"]
    return n


def p_http_socks(link, name_hint):
    u = urllib.parse.urlsplit(link)
    typ = "socks5" if link.startswith("socks") else "http"
    if not (u.hostname and u.port):
        return None
    n = {"name": clean_name(u.fragment, name_hint), "type": typ, "server": u.hostname, "port": u.port, "udp": False}
    if u.username:
        n["username"] = urllib.parse.unquote(u.username)
    if u.password:
        n["password"] = urllib.parse.unquote(u.password)
    return n


PARSERS = {
    "vmess": p_vmess, "vless": p_vless, "trojan": p_trojan, "ss": p_ss,
    "hysteria2": p_hysteria2, "hy2": p_hysteria2, "hysteria": p_hysteria,
    "tuic": p_tuic, "socks5": p_http_socks, "socks": p_http_socks, "http": p_http_socks,
}

LINK_RE = re.compile(r"(vmess|vless|trojan|ss|hysteria2|hy2|hysteria|tuic|socks5|socks|http)://[^\s\"'<>\\]+")


def parse_links(text, src):
    out = []
    for i, m in enumerate(LINK_RE.finditer(text)):
        scheme = m.group(1)
        fn = PARSERS.get(scheme)
        if not fn:
            continue                      # ssr / wireguard 等不支持，直接跳过
        link = m.group(0).rstrip(",;)")
        try:
            n = fn(link, f"{src}-{i}")
        except Exception:
            n = None
        if n:
            n["_src"] = src
            out.append(n)
    return out


def parse_clash_yaml(text, src):
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        log(f"  [warn] {src}: YAML 解析失败 {e}")
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for i, p in enumerate(doc.get("proxies") or []):
        if not isinstance(p, dict) or not p.get("type"):
            continue
        p = dict(p)
        p.setdefault("name", f"{src}-{i}")
        p["_src"] = src
        out.append(p)
    return out


def parse_iplist(text, src, tls_hint=False):
    """解析 ip:port 列表。兼容这些写法：
       1.2.3.4:8080
       http://1.2.3.4:8080 / https://1.2.3.4:8080 / socks5://1.2.3.4:1080
       user:pass@1.2.3.4:8080
       1.2.3.4:9002:The Netherlands        （第三列是国家，zloi-user 那种）
    """
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        scheme = ""
        m0 = re.match(r"^(https?|socks5?)://", s, re.I)
        if m0:
            scheme = m0.group(1).lower()
            s = s[m0.end():]
        userinfo = None
        if "@" in s:
            head, _, s = s.rpartition("@")
            userinfo = head
        m = re.match(r"^((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9.\-]*):(\d{1,5})(?::(.*))?$", s)
        if not m:
            continue
        host, port, extra = m.group(1), as_int(m.group(2)), (m.group(3) or "").strip()
        if not (1 <= port <= 65535):
            continue
        if scheme == "socks4":
            continue          # mihomo 与 sing-box 都没有 SOCKS4 出站，收了也无法用（实测确认）
        typ = "socks5" if scheme.startswith("socks") else "http"
        n = {"name": f"{src}-{host}", "type": typ, "server": host.strip("[]"), "port": port,
             "udp": False, "_src": src}
        if userinfo and ":" in userinfo:
            u, _, pw = userinfo.partition(":")
            if u:
                n["username"], n["password"] = u, pw
        if extra:
            n["_country"] = extra[:24]
        if tls_hint or scheme == "https":
            n["_tls_hint"] = True
        out.append(n)
    return out


def load_discovered_sources():
    """并入 discover_sources.py 自动发现的源"""
    path = os.environ.get("DISCOVERED", "discovered_sources.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            arr = json.load(f)
    except Exception:
        return []
    known = {s["url"] for s in SOURCES}
    out = []
    for s in arr:
        if isinstance(s, dict) and s.get("url") and s["url"] not in known:
            out.append({"name": s.get("name", s["url"])[:28], "url": s["url"], "fmt": s.get("fmt", "auto")})
    return out


def collect():
    all_nodes, stats = [], []
    sources = SOURCES + load_discovered_sources()
    for s in sources:
        try:
            text = http_get(s["url"])
        except Exception as e:
            log(f"  [FAIL] {s['name']:26} 拉取失败 {str(e)[:70]}")
            stats.append((s["name"], "拉取失败", 0))
            continue
        fmt = s["fmt"]
        if fmt == "auto":
            body = text.strip()
            head = body[:4000]
            first = head.splitlines()[0] if head else ""
            if "proxies:" in head:
                fmt = "clash"
            elif re.search(r"^(vmess|vless|trojan|ss|hysteria2?|tuic|socks5?|http)://", head, re.M):
                fmt = "links"
            elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\s*$", first):
                fmt = "iplist"
            else:
                dec = b64decode_any(body)
                if re.search(r"\w+://", dec or ""):
                    fmt = "links-b64"
                elif dec and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}", dec.strip()):
                    fmt = "iplist-b64"
                else:
                    fmt = "links"
        try:
            if fmt == "clash":
                nodes = parse_clash_yaml(text, s["name"])
            elif fmt == "iplist":
                nodes = parse_iplist(text, s["name"], s.get("tls_hint", False))
            elif fmt == "iplist-b64":
                nodes = parse_iplist(b64decode_any(text.strip()), s["name"], s.get("tls_hint", False))
            elif fmt == "links-b64":
                nodes = parse_links(b64decode_any(text.strip()), s["name"])
            else:
                nodes = parse_links(text, s["name"])
        except Exception as e:
            log(f"  [FAIL] {s['name']:26} 解析失败 {str(e)[:70]}")
            stats.append((s["name"], "解析失败", 0))
            continue
        nodes = [n for n in nodes if n.get("server") and n.get("port")
                 and is_public_host(str(n["server"])) and n.get("type") in SUPPORTED]
        nodes = nodes[:MAX_PER_SOURCE]
        log(f"  [ OK ] {s['name']:26} {len(nodes):>5} 条")
        stats.append((s["name"], "ok", len(nodes)))
        all_nodes.extend(nodes)
    return all_nodes, stats


# ---------------------------------------------------------------- 检测
def tcp_latency(server, port):
    t0 = time.time()
    try:
        infos = socket.getaddrinfo(server, port, proto=socket.IPPROTO_TCP)
        if not infos:
            return None
        fam, stype, proto, _, sa = infos[0]
        s = socket.socket(fam, stype, proto)
        s.settimeout(TCP_TIMEOUT)
        try:
            s.connect(sa)
        finally:
            s.close()
        return int((time.time() - t0) * 1000)
    except Exception:
        return None


def http_func_test(server, port, extra=None):
    """对 HTTP 代理做真实请求验证，不是只看端口能不能连"""
    for url in TEST_URLS:
        try:
            u = urllib.parse.urlsplit(url)
            auth = ""
            if extra and extra.get("username"):
                tok = base64.b64encode(f"{extra['username']}:{extra.get('password','')}".encode()).decode()
                auth = f"Proxy-Authorization: Basic {tok}\r\n"
            s = socket.create_connection((server, port), timeout=6)
            s.settimeout(6)
            req = (f"GET {url} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: {UA}\r\n"
                   f"{auth}Proxy-Connection: close\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            head = s.recv(256)
            s.close()
            if re.match(rb"HTTP/1\.[01] (200|204)", head or b""):
                return True
        except Exception:
            continue
    return False


def dedupe(nodes):
    seen, out = set(), []
    for n in nodes:
        key = (n.get("type"), str(n.get("server", "")).lower(), n.get("port"),
               n.get("uuid") or n.get("password") or n.get("username") or "",
               n.get("network", ""), (n.get("ws-opts") or {}).get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def test_all(nodes):
    log(f"\n开始检测 {len(nodes)} 个节点（TCP 连通性 + 延迟，超时 {TCP_TIMEOUT}s）…")
    alive, t0 = [], time.time()
    done = 0
    with cf.ThreadPoolExecutor(max_workers=300) as ex:
        futs = {ex.submit(tcp_latency, str(n["server"]), int(n["port"])): n for n in nodes}
        for f in cf.as_completed(futs):
            n = futs[f]
            try:
                ms = f.result()
            except Exception:
                ms = None
            done += 1
            if done % 1000 == 0:
                log(f"  …已测 {done}/{len(nodes)}，存活 {len(alive)}")
            if ms is not None:
                n["_latency"] = ms
                alive.append(n)
    log(f"TCP 存活 {len(alive)}/{len(nodes)}，耗时 {time.time()-t0:.0f}s")

    # HTTP 代理再做一次真实请求验证
    https = [n for n in alive if n["type"] == "http"]
    https.sort(key=lambda x: x["_latency"])
    probe = https[:HTTP_FUNC_LIMIT]
    if probe:
        log(f"对 {len(probe)} 个 HTTP 代理做真实请求验证…")
        ok = set()
        with cf.ThreadPoolExecutor(max_workers=80) as ex:
            futs = {ex.submit(http_func_test, n["server"], n["port"], n): i for i, n in enumerate(probe)}
            for f in cf.as_completed(futs):
                try:
                    if f.result():
                        ok.add(futs[f])
                except Exception:
                    pass
        log(f"HTTP 真实可用 {len(ok)}/{len(probe)}")
        for i, n in enumerate(probe):
            n["_export"] = i in ok
        for n in https[len(probe):]:
            n["_export"] = False
    for n in alive:
        if n["type"] != "http":
            n["_export"] = True
    return alive


# ---------------------------------------------------------------- 输出
def yaml_dump(obj):
    return yaml.safe_dump(obj, allow_unicode=True, sort_keys=False, width=1000)


def clash_proxy(n, idx):
    p = {k: v for k, v in n.items() if not k.startswith("_")}
    p["name"] = clean_name(n.get("name"), f"node-{idx}") + f" [{n.get('_src','?')[:12]}|{n.get('_latency',0)}ms]"
    order = ["name", "type", "server", "port", "uuid", "password", "cipher", "alterId", "udp",
             "tls", "sni", "servername", "skip-cert-verify", "network", "ws-opts", "grpc-opts",
             "h2-opts", "reality-opts", "client-fingerprint", "flow", "alpn", "obfs", "obfs-password",
             "username", "up", "down", "auth-str", "congestion-controller"]
    return {k: p[k] for k in order if k in p} | {k: v for k, v in p.items() if k not in order}


def build_clash(proxies, names, http_names):
    groups = [{
        "name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
        "interval": 300, "tolerance": 50, "lazy": False, "proxies": names[:200] or ["DIRECT"],
    }, {
        "name": "🌐 HTTP 专用", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
        "interval": 300, "tolerance": 50, "proxies": http_names[:200] or ["DIRECT"],
    }, {
        "name": "♻️ 故障转移", "type": "fallback", "url": "http://www.gstatic.com/generate_204",
        "interval": 300, "proxies": names[:100] or ["DIRECT"],
    }]
    return yaml_dump({
        "port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "external-controller": "127.0.0.1:9090",
        "proxies": proxies, "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 自动选择"],
    })


def build_page(stats, counts, files, updated):
    rows = "\n".join(
        f"<tr><td>{s}</td><td>{st}</td><td style='text-align:right'>{c}</td></tr>"
        for s, st, c in stats)
    proto = "\n".join(
        f"<span class='pill'>{k} <b>{v}</b></span>" for k, v in counts.most_common())
    cards = ""
    for label, fn, desc in files:
        cards += (f"<div class='card'><div class='fn'>{label}</div><div class='desc'>{desc}</div>"
                  f"<div class='url' onclick=\"cp(this)\">{fn}</div></div>")
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>免费节点订阅 · 自动更新</title>
<style>
:root{{color-scheme:dark light}}
body{{font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:900px;
margin:0 auto;padding:28px 18px 60px;line-height:1.6}}
h1{{font-size:24px;margin:0 0 4px}}
.sub{{opacity:.65;font-size:14px}}
.pill{{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 12px;margin:4px 6px 4px 0;font-size:13px;opacity:.85}}
.card{{border:1px solid #8884;border-radius:12px;padding:14px 16px;margin:12px 0}}
.fn{{font-weight:600}}
.desc{{font-size:13px;opacity:.65;margin:2px 0 8px}}
.url{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:#8882;border-radius:8px;
padding:9px 11px;word-break:break-all;cursor:pointer}}
.url:hover{{background:#8883}}
table{{border-collapse:collapse;width:100%;font-size:14px;margin-top:8px}}
td,th{{border-bottom:1px solid #8883;padding:7px 6px;text-align:left}}
th{{opacity:.6;font-weight:500}}
.warn{{border-left:3px solid #e0a020;padding:10px 14px;background:#e0a0201a;border-radius:8px;font-size:13.5px}}
h2{{font-size:17px;margin:26px 0 6px}}
</style></head><body>
<h1>免费节点订阅 · 自动更新</h1>
<div class="sub">最后更新：{updated}　|　可用节点 <b>{sum(counts.values())}</b> 个　|　源 {len(stats)} 个</div>
<div style="margin:16px 0">{proto}</div>
<h2>订阅地址（点一下复制）</h2>
{cards}
<h2>源站明细</h2>
<table><tr><th>源</th><th>状态</th><th style="text-align:right">抓取条数</th></tr>{rows}</table>
<h2>注意</h2>
<div class="warn">
免费公共节点由陌生人提供，<b>可能被记录、篡改或劫持流量</b>。不要用它登录银行、邮箱、公司账号等敏感服务；
只用于临时浏览。节点存活度很低，订阅地址每 6 小时自动刷新，客户端里设为自动更新即可。
</div>
<script>
function cp(e){{navigator.clipboard.writeText(e.textContent.trim());const t=e.textContent;
e.textContent='已复制 ✓';setTimeout(()=>e.textContent=t,900);}}
</script></body></html>"""


def to_share_link(n):
    """把统一节点转回分享链接，给只认 base64 订阅的客户端用"""
    t = n["type"]
    tag = urllib.parse.quote(clean_name(n.get("name"), n["server"]), safe="")
    net = n.get("network", "tcp")
    ws = n.get("ws-opts") or {}
    host = (ws.get("headers") or {}).get("Host", "")
    path = ws.get("path", "")
    try:
        if t == "vmess":
            j = {"v": "2", "ps": clean_name(n.get("name"), "node"), "add": n["server"], "port": str(n["port"]),
                 "id": n.get("uuid", ""), "aid": str(n.get("alterId", 0)), "scy": n.get("cipher", "auto"),
                 "net": net, "type": "none", "host": host, "path": path,
                 "tls": "tls" if n.get("tls") else "", "sni": n.get("servername", "")}
            return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()
        if t == "vless":
            q = {"type": net, "encryption": "none"}
            if n.get("tls"):
                q["security"] = "reality" if n.get("reality-opts") else "tls"
                if n.get("servername"):
                    q["sni"] = n["servername"]
            if n.get("flow"):
                q["flow"] = n["flow"]
            if net == "ws":
                q["path"], q["host"] = path, host
            if n.get("reality-opts"):
                q["pbk"] = n["reality-opts"].get("public-key", "")
                q["sid"] = n["reality-opts"].get("short-id", "")
            return f"vless://{n.get('uuid','')}@{n['server']}:{n['port']}?{urllib.parse.urlencode(q)}#{tag}"
        if t == "trojan":
            q = {}
            if n.get("sni"):
                q["sni"] = n["sni"]
            if net == "ws":
                q.update({"type": "ws", "path": path, "host": host})
            pw = urllib.parse.quote(str(n.get("password", "")), safe="")
            return f"trojan://{pw}@{n['server']}:{n['port']}?{urllib.parse.urlencode(q)}#{tag}"
        if t == "ss":
            userinfo = base64.b64encode(f"{n.get('cipher','')}:{n.get('password','')}".encode()).decode()
            userinfo = userinfo.rstrip("=")
            return f"ss://{userinfo}@{n['server']}:{n['port']}#{tag}"
        if t == "hysteria2":
            q = {}
            if n.get("sni"):
                q["sni"] = n["sni"]
            if n.get("obfs"):
                q["obfs"] = n["obfs"]
                if n.get("obfs-password"):
                    q["obfs-password"] = n["obfs-password"]
            pw = urllib.parse.quote(str(n.get("password", "")), safe="")
            return f"hysteria2://{pw}@{n['server']}:{n['port']}?{urllib.parse.urlencode(q)}#{tag}"
        if t == "tuic" and n.get("uuid"):
            q = {"sni": n.get("sni", ""), "alpn": ",".join(n.get("alpn") or ["h3"])}
            return (f"tuic://{n['uuid']}:{urllib.parse.quote(str(n.get('password','')), safe='')}"
                    f"@{n['server']}:{n['port']}?{urllib.parse.urlencode(q)}#{tag}")
    except Exception:
        return None
    return None


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    t_start = time.time()
    log("=" * 68)
    log("Step 1/2 拉取节点源")
    raw, stats = collect()
    log(f"原始 {len(raw)} 条")
    nodes = dedupe(raw)
    log(f"去重后 {len(nodes)} 条")
    nodes = nodes[:MAX_TOTAL_TEST]

    # 注意：这里**不做**可用性判定。
    # 早期版本在 GitHub 的海外机器上测存活，结果是从美国能通、从国内根本不能用的节点
    # （大量 Cloudflare 边缘 IP，从国内连会返回 409/error 1001）也进了订阅。
    # 真正的校验由 verify_cn.py 在本机按真实协议跑。
    log("\nStep 2/2 写出候选清单（不做可用性判定，交给本机真实校验）")
    cand = []
    for n in nodes:
        p = {k: v for k, v in n.items() if not k.startswith("_")}
        p["name"] = f"{str(n.get('_src','?'))[:16]}|{n['type']}|{n['server']}"
        # 这两项要跟着候选一起传下去（verify_cn 用它们决定先测 TLS 还是明文）
        p["x_country"] = n.get("_country", "")
        p["x_tls"] = bool(n.get("_tls_hint"))
        cand.append(p)
    with open(f"{OUT_DIR}/candidates.yaml", "w", encoding="utf-8") as f:
        f.write("# 全量候选节点（未做可用性判定）\n"
                f"# 由 GitHub Actions 搜集，真正的可用性校验在本机按真实协议执行\n"
                f"# 生成时间：{datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
                f"# 候选数：{len(cand)}\n" + yaml_dump({"proxies": cand}))
    log(f"候选清单已写出：{OUT_DIR}/candidates.yaml（{len(cand)} 个）")
    counts = Counter(n["type"] for n in nodes)
    updated = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M (UTC+8)")
    with open(f"{OUT_DIR}/stats.json", "w", encoding="utf-8") as f:
        json.dump({"updated_utc8": updated, "candidates": len(nodes), "counts": counts,
                   "sources": [{"name": a, "status": b, "count": c} for a, b, c in stats],
                   "seconds": round(time.time() - t_start, 1)}, f, ensure_ascii=False, indent=2)
    log(f"\n完成，用时 {time.time()-t_start:.0f}s，输出到 {OUT_DIR}/")


def main_legacy():
    """海外侧存活检测 + 生成订阅。默认不使用：判定地点错误，会混入国内不可用的节点。"""
    os.makedirs(OUT_DIR, exist_ok=True)
    t_start = time.time()
    log("=" * 68)
    log("Step 1/4 拉取节点源")
    raw, stats = collect()
    log(f"原始 {len(raw)} 条")
    nodes = dedupe(raw)
    log(f"去重后 {len(nodes)} 条")
    nodes = nodes[:MAX_TOTAL_TEST]

    log("\nStep 2/4 存活检测（海外侧，仅供参考）")
    alive = test_all(nodes) if nodes else []

    log("\nStep 3/4 排序")
    prio = {"http": 0, "socks5": 1, "hysteria2": 2, "trojan": 3, "vless": 4, "ss": 5, "vmess": 6,
            "tuic": 7, "hysteria": 8}
    alive = [n for n in alive if n.get("_export")]
    alive.sort(key=lambda n: (prio.get(n["type"], 9), n["_latency"]))
    counts = Counter(n["type"] for n in alive)
    log(f"最终导出 {len(alive)} 个：" + "，".join(f"{k} {v}" for k, v in counts.most_common()))

    log("\nStep 4/4 生成订阅")
    built, names, v2ray_links = [], [], []
    for i, n in enumerate(alive):
        p = clash_proxy(n, i)
        if p["name"] in names:
            p["name"] = f"{p['name']}#{i}"
        built.append(p)
        names.append(p["name"])
        link = to_share_link(n)
        if link:
            v2ray_links.append(link)
    http_nodes = [n for n in alive if n["type"] == "http"]
    http_names = [p["name"] for p in built if p["type"] == "http"]

    with open(f"{OUT_DIR}/clash.yaml", "w", encoding="utf-8") as f:
        f.write("# 自动生成的免费节点订阅（Clash / mihomo / Clash Meta）\n"
                f"# 生成时间：{datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
                f"# 节点数：{len(built)}\n" + build_clash(built, names, http_names))

    with open(f"{OUT_DIR}/http.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(
            (f"{n.get('username')}:{n.get('password')}@" if n.get("username") else "") + f"{n['server']}:{n['port']}"
            for n in http_nodes) + ("\n" if http_nodes else ""))

    hb, hn = [], []
    for i, n in enumerate(http_nodes):
        p = clash_proxy(n, i)
        if p["name"] in hn:
            p["name"] = f"{p['name']}#{i}"
        hb.append(p)
        hn.append(p["name"])
    with open(f"{OUT_DIR}/http.yaml", "w", encoding="utf-8") as f:
        f.write(build_clash(hb, hn, hn) if hb else "# 本次没有可用的 HTTP 代理\n")

    with open(f"{OUT_DIR}/v2ray.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(v2ray_links).encode()).decode() if v2ray_links else "")

    updated = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M (UTC+8)")
    with open(f"{OUT_DIR}/index.html", "w", encoding="utf-8") as f:
        f.write(build_page(stats, counts, [
            ("Clash / mihomo 订阅", "clash.yaml", f"全部可用节点 {len(built)} 个，含 HTTP 代理优先排序"),
            ("仅 HTTP 代理（ip:port 文本）", "http.txt", f"{len(http_nodes)} 个，已通过真实请求验证"),
            ("仅 HTTP 代理（Clash）", "http.yaml", f"{len(http_nodes)} 个"),
        ], updated))
    with open(f"{OUT_DIR}/stats.json", "w", encoding="utf-8") as f:
        json.dump({"updated_utc8": updated, "alive": len(built), "counts": counts,
                   "http_verified": len(http_nodes), "sources": [{"name": a, "status": b, "count": c} for a, b, c in stats],
                   "seconds": round(time.time() - t_start, 1)}, f, ensure_ascii=False, indent=2)

    log(f"\n完成，用时 {time.time()-t_start:.0f}s，输出到 {OUT_DIR}/")


if __name__ == "__main__":
    main()
