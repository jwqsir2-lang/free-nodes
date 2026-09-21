#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本机（国内）真实协议校验器
--------------------------------------------------
把候选节点喂给 mihomo 内核，通过 Clash API 的 /proxies/<name>/delay
逐个发起**真实请求**（默认打被墙的 gstatic/generate_204）。
只有真正能穿透的节点才会被写进订阅。

用法：
    python verify_cn.py                 # 从远端拉候选并校验
    python verify_cn.py --input x.yaml  # 用本地候选文件
    python verify_cn.py --limit 3000    # 只测前 N 个
"""
import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "dist", "cn")
WORK = os.path.join(HERE, ".verify_work")
MIHOMO = os.path.join(HERE, "tools", "mihomo.exe")

CANDIDATE_URLS = [
    "https://raw.githubusercontent.com/jwqsir2-lang/free-nodes/main/dist/candidates.yaml",
    "https://cdn.jsdelivr.net/gh/jwqsir2-lang/free-nodes@main/dist/candidates.yaml",
]
TEST_URLS = ["http://www.gstatic.com/generate_204", "http://www.google.com/generate_204"]
DELAY_TIMEOUT_MS = int(os.environ.get("DELAY_TIMEOUT_MS", "5000"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "96"))

NET_PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
if NET_PROXY:                       # 只用于下载候选文件
    _dl = urllib.request.build_opener(urllib.request.ProxyHandler({"http": NET_PROXY, "https": NET_PROXY}))
else:
    _dl = urllib.request.build_opener()
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 访问本机 API 用

# mihomo 子进程必须直连拨号，否则会绕进系统代理，测出来的就不算数了
CLEAN_ENV = {k: v for k, v in os.environ.items()
             if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}


def log(*a):
    print(*a, flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------- 取候选
def load_candidates(path=None):
    if path:
        text = open(path, encoding="utf-8").read()
        log(f"从本地文件读取候选：{path}")
    else:
        text, err = None, None
        for u in CANDIDATE_URLS:
            try:
                with _dl.open(u, timeout=60) as r:
                    text = r.read().decode("utf-8", "ignore")
                log(f"已拉取候选：{u}（{len(text)} 字符）")
                break
            except Exception as e:
                err = e
        if text is None:
            raise SystemExit(f"候选文件拉取失败：{err}")
    doc = yaml.safe_load(text)
    proxies = [p for p in (doc.get("proxies") or []) if isinstance(p, dict) and p.get("server") and p.get("port")]
    log(f"候选节点 {len(proxies)} 个")
    return proxies


def normalize(proxies):
    """净化 + 统一改名。mihomo 解析极严格：任何字段非法都会让整份配置失败，
    所以这里按类型白名单过滤掉不合法/不支持的字段，坏节点直接丢弃。"""
    out, seen = [], set()
    dropped = 0
    for i, raw in enumerate(proxies):
        p = sanitize(raw)
        if not p:
            dropped += 1
            continue
        p["_src"] = str(raw.get("name", "")).split("|")[0][:16] or "?"
        p["_country"] = str(raw.get("x_country") or "")[:24]
        p["_tls_hint"] = bool(raw.get("x_tls"))
        tag = f"n{i:05d}|{p['type']}|{str(p['server'])[:24]}"
        if tag in seen:
            continue
        seen.add(tag)
        p["name"] = tag
        out.append(p)
    log(f"净化后 {len(out)} 个（丢弃不合法 {dropped} 个）")
    return out


SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "chacha20-ietf-poly1305", "chacha20-poly1305",
    "xchacha20-ietf-poly1305", "chacha20-ietf", "chacha20", "rc4-md5", "none",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
VMESS_CIPHERS = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305"}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
SUPPORTED_TYPES = {"vmess", "vless", "trojan", "ss", "hysteria2", "hysteria", "http", "socks5", "tuic"}

COMMON_KEYS = {"name", "type", "server", "port", "udp", "tls", "sni", "servername", "skip-cert-verify",
               "client-fingerprint", "alpn", "network", "interface-name", "routing-mark", "ip-version",
               "dialer-proxy", "tfo", "mptcp", "smux"}
TYPE_KEYS = {
    "vmess": {"uuid", "alterId", "cipher", "ws-opts", "grpc-opts", "h2-opts", "http-opts", "packet-encoding"},
    "vless": {"uuid", "flow", "reality-opts", "ws-opts", "grpc-opts", "h2-opts", "http-opts", "packet-encoding"},
    "trojan": {"password", "ws-opts", "grpc-opts", "ss-opts", "flow"},
    "ss": {"cipher", "password", "plugin", "plugin-opts", "udp-over-tcp"},
    "hysteria2": {"password", "obfs", "obfs-password", "up", "down", "ca", "ca-str", "fingerprint",
                  "hop-interval", "ports", "auth"},
    "hysteria": {"auth-str", "auth", "up", "down", "obfs", "ca", "ca-str", "fingerprint", "protocol",
                 "recv-window", "disable-mtu-discovery", "fast-open"},
    "http": {"username", "password", "headers"},
    "socks5": {"username", "password"},
    "tuic": {"uuid", "password", "congestion-controller", "udp-relay-mode", "reduce-rtt",
             "heartbeat-interval", "disable-sni", "max-udp-relay-packet-size"},
}
NETS = {"tcp", "ws", "grpc", "h2", "http"}


def _b64_bytes(s, n):
    try:
        b = base64.urlsafe_b64decode(str(s).strip() + "=" * (-len(str(s).strip()) % 4))
        return len(b) == n
    except Exception:
        return False


def sanitize(p):
    if not isinstance(p, dict):
        return None
    typ = str(p.get("type", "")).lower()
    if typ not in SUPPORTED_TYPES:
        return None
    server = str(p.get("server") or "").strip().strip("[]")
    try:
        port = int(p.get("port"))
    except Exception:
        return None
    if not server or not (1 <= port <= 65535):
        return None

    q = {k: v for k, v in p.items()
         if not k.startswith("_") and (k in COMMON_KEYS or k in TYPE_KEYS.get(typ, set()))}
    q["type"], q["server"], q["port"] = typ, server, port

    if q.get("network") not in NETS:
        q.pop("network", None)
    if q.get("network") == "http":
        q["network"] = "h2"
    alpn = q.get("alpn")
    if alpn is not None:
        if isinstance(alpn, list) and all(isinstance(a, str) and 0 < len(a) < 32 for a in alpn):
            q["alpn"] = alpn
        else:
            q.pop("alpn", None)

    if typ in ("vmess", "vless"):
        if not UUID_RE.match(str(q.get("uuid", ""))):
            return None
    if typ == "vmess":
        c = str(q.get("cipher") or "auto").lower()
        q["cipher"] = c if c in VMESS_CIPHERS else "auto"
        try:
            q["alterId"] = int(q.get("alterId") or 0)
        except Exception:
            q["alterId"] = 0
    if typ == "vless":
        ro = q.get("reality-opts")
        if ro is not None:
            if not isinstance(ro, dict):
                return None
            pk, sid = str(ro.get("public-key", "")), str(ro.get("short-id", "") or "")
            if not _b64_bytes(pk, 32) or not (HEX_RE.match(sid) and len(sid) % 2 == 0 and len(sid) <= 16):
                return None          # 公钥/短 ID 非法，这个节点必然是坏的
            q["reality-opts"] = {"public-key": pk, **({"short-id": sid} if sid else {})}
    if typ == "ss":
        if str(q.get("cipher", "")).lower() not in SS_CIPHERS:
            return None
        q["cipher"] = str(q["cipher"]).lower()
        if not q.get("password"):
            return None
        if q.get("plugin"):                      # 插件参数缺失率高，直接丢弃
            return None
    if typ in ("trojan", "hysteria2", "tuic") and not (q.get("password") or q.get("uuid")):
        return None
    if typ == "hysteria2":
        if q.get("obfs") not in (None, "salamander"):
            q.pop("obfs", None)
            q.pop("obfs-password", None)
        elif q.get("obfs") == "salamander" and not q.get("obfs-password"):
            q.pop("obfs", None)
    if typ == "tuic":
        if not UUID_RE.match(str(q.get("uuid", ""))):
            return None
        if q.get("congestion-controller") not in (None, "cubic", "new_reno", "bbr"):
            q.pop("congestion-controller", None)
    if typ in ("http", "socks5"):
        for k in ("username", "password"):
            if k in q and not isinstance(q[k], str):
                q[k] = str(q[k])
        if q.get("username") == "":
            q.pop("username", None)
            q.pop("password", None)
    for k in ("ws-opts", "grpc-opts", "h2-opts"):
        if k in q and not isinstance(q[k], dict):
            q.pop(k, None)
    if q.get("udp") not in (True, False):
        q["udp"] = False
    return q


# ---------------------------------------------------------------- 变体展开
TLS_LIKELY_PORTS = (443, 8443, 2087, 2096, 8843, 4443)


def expand_variants(proxies):
    """HTTP 代理有两种形态：明文 HTTP，或被 TLS 包起来的 HTTPS 代理。
    节点列表里不会标，所以同一个 host:port 生成两个变体都真测一遍，
    按端口和来源决定先试哪个（443 端口和 https 来源先试 TLS）。"""
    out = []
    n_http = 0
    for p in proxies:
        if p.get("type") != "http":
            p["_variant"] = ""
            out.append(p)
            continue
        n_http += 1
        base = {k: v for k, v in p.items()
                if k not in ("tls", "servername", "sni", "skip-cert-verify")}
        plain = dict(base, _variant="plain")
        tls = dict(base, _variant="tls", tls=True)
        tls["skip-cert-verify"] = True
        tls["servername"] = str(p.get("servername") or p.get("sni") or p["server"])
        plain["name"] = p["name"] + "|P"
        tls["name"] = p["name"] + "|T"
        if p.get("_tls_hint") or p["port"] in TLS_LIKELY_PORTS:
            out += [tls, plain]
        else:
            out += [plain, tls]
    log(f"HTTP 代理展开为明文/TLS 两个变体：{n_http} → {n_http * 2} 个待测")
    return out


# ---------------------------------------------------------------- mihomo
class Mihomo:
    def __init__(self, proxies):
        self.proxies = proxies
        self.api_port = free_port()
        self.dir = WORK
        os.makedirs(self.dir, exist_ok=True)
        self.proc = None

    def _build_cfg(self, proxies):
        return {
            "mixed-port": free_port(),
            "external-controller": f"127.0.0.1:{self.api_port}",
            "mode": "rule",
            "log-level": "silent",
            "ipv6": False,
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",     # 关键：域名交给代理远端解析，绕开本地 DNS 污染
                "fake-ip-range": "198.18.0.1/16",
                "nameserver": ["223.5.5.5", "119.29.29.29"],
                "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            },
            "proxies": [{k: v for k, v in p.items() if not k.startswith("_")} for p in proxies],
            "proxy-groups": [{"name": "ALL", "type": "select",
                              "proxies": [p["name"] for p in proxies]}],
            "rules": ["MATCH,ALL"],
        }

    def _write_cfg(self, proxies, path):
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(self._build_cfg(proxies), f, allow_unicode=True, sort_keys=False, width=1000)

    def _test_cfg(self, proxies):
        """用 mihomo -t 校验配置；失败时它会把第一个坏节点的下标写在 msg 里"""
        path = os.path.join(self.dir, "probe.yaml")
        self._write_cfg(proxies, path)
        r = subprocess.run([MIHOMO, "-f", path, "-d", self.dir, "-t"],
                           capture_output=True, text=True, timeout=600, env=CLEAN_ENV)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r'msg="proxy (\d+): ([^"]*)"', out)
        return r.returncode == 0, (int(m.group(1)) if m else None), (m.group(2) if m else out.strip()[-160:])

    def validate(self, proxies, max_removals=2000):
        """mihomo 解析极严格，任何一个节点不合法都会让整份配置失败。
        这里让它自己当裁判，按报错下标逐个剔除。"""
        lst, removed = list(proxies), []
        for _ in range(max_removals + 1):
            ok, idx, msg = self._test_cfg(lst)
            if ok:
                break
            if idx is None or not (0 <= idx < len(lst)):
                log(f"  [warn] 无法定位坏节点（{msg[:90]}），放弃本轮剩余 {len(lst)} 个")
                lst = []
                break
            removed.append((msg, lst[idx]))
            del lst[idx]
        else:
            log("  [warn] 剔除次数达到上限，可能仍有非法节点")
        if removed:
            log(f"  剔除 mihomo 拒绝的节点 {len(removed)} 个（原因样例）：")
            seen = set()
            for msg, p in removed:
                if msg in seen:
                    continue
                seen.add(msg)
                log(f"    - {p.get('type')} {p.get('server')}:{p.get('port')} → {msg}")
                if len(seen) >= 5:
                    break
        return lst

    def start(self):
        os.makedirs(self.dir, exist_ok=True)
        log(f"用 mihomo 校验配置合法性（{len(self.proxies)} 个节点）…")
        self.proxies = self.validate(self.proxies)
        if not self.proxies:
            raise SystemExit("没有任何节点能通过 mihomo 的配置解析")
        path = os.path.join(self.dir, "config.yaml")
        self._write_cfg(self.proxies, path)
        log(f"启动 mihomo（{len(self.proxies)} 个节点，API 127.0.0.1:{self.api_port}）…")
        self.proc = subprocess.Popen(
            [MIHOMO, "-f", path, "-d", self.dir],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=self.dir, env=CLEAN_ENV,
        )
        for _ in range(60):
            try:
                self._get("/version", timeout=2)
                log("mihomo 就绪")
                return True
            except Exception:
                if self.proc.poll() is not None:
                    raise SystemExit("mihomo 启动失败（进程已退出）")
                time.sleep(1)
        raise SystemExit("mihomo 启动超时")

    def _get(self, path, timeout=15):
        req = urllib.request.Request(f"http://127.0.0.1:{self.api_port}{path}")
        with NO_PROXY_OPENER.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def delay(self, name, url, timeout_ms):
        q = urllib.parse.urlencode({"url": url, "timeout": str(timeout_ms)})
        try:
            return self._get(f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}",
                             timeout=timeout_ms / 1000 + 8).get("delay")
        except Exception:
            return None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass


def test_all(m, proxies):
    log(f"\n开始真实协议校验：{len(proxies)} 个节点 × 超时 {DELAY_TIMEOUT_MS}ms × 并发 {CONCURRENCY}")
    results = {}
    done = 0
    t0 = time.time()

    def work(p):
        for url in TEST_URLS:
            d = m.delay(p["name"], url, DELAY_TIMEOUT_MS)
            if d:
                return p["name"], d, url
        return p["name"], None, None

    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = [ex.submit(work, p) for p in proxies]
        for f in cf.as_completed(futs):
            try:
                name, d, url = f.result()
            except Exception:
                name, d, url = None, None, None
            done += 1
            if d:
                results[name] = (d, url)
            if done % 500 == 0:
                log(f"  …{done}/{len(proxies)}，已确认可用 {len(results)}，用时 {time.time()-t0:.0f}s")
    log(f"真实校验完成：{len(results)}/{len(proxies)} 可用，用时 {time.time()-t0:.0f}s")
    return results


# ---------------------------------------------------------------- 输出
def build_outputs(proxies, results):
    os.makedirs(OUT_DIR, exist_ok=True)
    ok = []
    for p in proxies:
        r = results.get(p["name"])
        if not r:
            continue
        q = {k: v for k, v in p.items() if not k.startswith("_")}
        q["_delay"] = r[0]
        q["_variant"] = p.get("_variant", "")
        q["_src"] = p.get("_src", "?")
        q["_country"] = p.get("_country", "")
        ok.append(q)

    # 同一个 host:port 只保留一个变体：TLS 优先（能走 TLS 就不必走明文）
    best = {}
    for p in ok:
        key = (p["server"], p["port"], p["type"])
        cur = best.get(key)
        if cur is None or (p["_variant"] == "tls" and cur["_variant"] != "tls"):
            best[key] = p
    ok = list(best.values())
    n_tls = sum(1 for p in ok if p.get("type") == "http" and p.get("tls"))
    prio = {"http": 0, "socks5": 1, "hysteria2": 2, "trojan": 3, "vless": 4, "ss": 5, "vmess": 6, "hysteria": 7, "tuic": 8}
    ok.sort(key=lambda x: (prio.get(x.get("type"), 9), x["_delay"]))
    log(f"排序后可用节点 {len(ok)} 个：" + "，".join(
        f"{t} {c}" for t, c in
        sorted(((t, sum(1 for x in ok if x.get("type") == t)) for t in {x.get("type") for x in ok}),
               key=lambda k: -k[1])))

    names = []
    for i, p in enumerate(ok):
        local = p.get("_country") or p["server"]
        kind = "https" if (p.get("type") == "http" and p.get("tls")) else p.get("type", "?")
        base = f"{kind}|{local[:20]}:{p['port']}|{p['_delay']}ms|{p['_src'][:12]}"
        if base in names:
            base += f"#{i}"
        p["name"] = base
        names.append(p["name"])
    clash = {
        "port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "external-controller": "127.0.0.1:9090",
        "proxies": [{k: v for k, v in p.items() if not k.startswith("_")} for p in ok],
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": TEST_URLS[0], "interval": 300,
             "tolerance": 50, "proxies": names[:200] or ["DIRECT"]},
            {"name": "🌐 HTTP/HTTPS 专用", "type": "url-test", "url": TEST_URLS[0], "interval": 300,
             "proxies": [p["name"] for p in ok if p.get("type") == "http"][:200] or ["DIRECT"]},
            {"name": "🔒 带 TLS 的 HTTP", "type": "url-test", "url": TEST_URLS[0], "interval": 300,
             "proxies": [p["name"] for p in ok if p.get("type") == "http" and p.get("tls")][:200] or ["DIRECT"]},
            {"name": "♻️ 故障转移", "type": "fallback", "url": TEST_URLS[0], "interval": 300,
             "proxies": names[:100] or ["DIRECT"]},
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 自动选择"],
    }
    header = ("# 已在本机（国内）通过真实协议端到端校验\n"
              f"# 校验时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} (本地时间)\n"
              f"# 校验目标：{' / '.join(TEST_URLS)}（被墙域名，能通才收录）\n"
              f"# 可用节点：{len(ok)}（HTTP 代理中带 TLS 的 {n_tls} 个）\n")
    with open(os.path.join(OUT_DIR, "clash.yaml"), "w", encoding="utf-8") as f:
        f.write(header + yaml.safe_dump(clash, allow_unicode=True, sort_keys=False, width=1000))

    # 只要 HTTP 代理，形态与 clash.yaml 完全一致（完整参数条目，不是裸 ip:port）
    http_ok = [p for p in ok if p.get("type") == "http"]
    http_tls_n = sum(1 for p in http_ok if p.get("tls"))
    hnames = [p["name"] for p in http_ok]
    http_clash = dict(clash)
    http_clash["proxies"] = [{k: v for k, v in p.items() if not k.startswith("_")} for p in http_ok]
    http_clash["proxy-groups"] = [
        {"name": "🚀 自动选择", "type": "url-test", "url": TEST_URLS[0], "interval": 300,
         "tolerance": 50, "proxies": hnames[:200] or ["DIRECT"]},
        {"name": "🔒 带 TLS 的 HTTP", "type": "url-test", "url": TEST_URLS[0], "interval": 300,
         "proxies": [p["name"] for p in http_ok if p.get("tls")][:200] or ["DIRECT"]},
        {"name": "🌐 全部 HTTP", "type": "select", "proxies": hnames[:300] or ["DIRECT"]},
    ]
    with open(os.path.join(OUT_DIR, "http.yaml"), "w", encoding="utf-8") as f:
        f.write(f"# 仅 HTTP/HTTPS 代理，共 {len(http_ok)} 个（其中带 TLS 的 {http_tls_n} 个）\n"
                f"# 字段与 cn/clash.yaml 里的条目完全一致\n"
                + yaml.safe_dump(http_clash, allow_unicode=True, sort_keys=False, width=1000))

    # sing-box / Karing：与客户端导出条目一一对应的 outbounds 数组
    outbounds = []
    for p in http_ok:
        ob = {
            "__id_in_gui": "ID_" + hashlib.md5(f"{p['server']}:{p['port']}".encode()).hexdigest()[:9],
            "tag": p["name"],
            "type": "http",
            "server": p["server"],
            "server_port": p["port"],
        }
        if p.get("username"):
            ob["username"] = p["username"]
            ob["password"] = p.get("password", "")
        if p.get("tls"):
            ob["tls"] = {"enabled": True,
                         "server_name": p.get("servername") or p.get("sni") or p["server"],
                         "insecure": True}
        outbounds.append(ob)
    with open(os.path.join(OUT_DIR, "http-outbounds.json"), "w", encoding="utf-8") as f:
        json.dump(outbounds, f, ensure_ascii=False, indent=2)

    with open(os.path.join(OUT_DIR, "http.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(
            (f"{p.get('username')}:{p.get('password')}@" if p.get("username") else "")
            + f"{p['server']}:{p['port']}" for p in http_ok) + ("\n" if http_ok else ""))

    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location("fn", os.path.join(HERE, "fetch_nodes.py"))
    fn = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fn)
    links = [l for l in (fn.to_share_link(p) for p in ok if p.get("type") != "http") if l]
    with open(os.path.join(OUT_DIR, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode() if links else "")

    from collections import Counter
    counts = Counter(p.get("type") for p in ok)
    stats = {
        "verified_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_targets": TEST_URLS,
        "candidates": len(proxies),
        "alive": len(ok),
        "counts": dict(counts),
        "http_total": len(http_ok),
        "http_tls": http_tls_n,
        "fastest": [{"name": p["name"], "delay": p["_delay"], "type": p.get("type"),
                     "tls": bool(p.get("tls"))} for p in ok[:20]],
    }
    with open(os.path.join(OUT_DIR, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    log(f"已写入 {OUT_DIR}/：clash.yaml、http.yaml、http-outbounds.json、http.txt、v2ray.txt")
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="本地候选 YAML")
    ap.add_argument("--limit", type=int, default=int(os.environ.get("LIMIT", "40000")))
    ap.add_argument("--http-limit", type=int, default=int(os.environ.get("HTTP_LIMIT", "3000")),
                    help="HTTP 代理最多测多少个（实测通过率极低，全测浪费预算）")
    ap.add_argument("--no-push", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(MIHOMO):
        raise SystemExit(f"找不到 mihomo：{MIHOMO}")
    all_cands = normalize(load_candidates(args.input))
    # 上限只作用于 http：http 候选动辄上万，会把 vless/vmess 这些挤掉
    non_http = [p for p in all_cands if p.get("type") != "http"]
    http = [p for p in all_cands if p.get("type") == "http"]
    log(f"非 http 候选 {len(non_http)} 个（全部测），http 候选 {len(http)} 个")
    if args.http_limit and len(http) > args.http_limit:
        # 优先留 https 来源和 443/8443 端口的，它们才可能是 TLS 代理
        http.sort(key=lambda p: (not p.get("_tls_hint"), p["port"] not in TLS_LIKELY_PORTS))
        log(f"http 只取前 {args.http_limit} 个（优先 TLS 可能性高的）")
        http = http[:args.http_limit]
    proxies = non_http + http
    if args.limit and len(proxies) > args.limit:
        log(f"总数超上限 {args.limit}，截断")
        proxies = proxies[:args.limit]
    proxies = expand_variants(proxies)
    m = Mihomo(proxies)
    try:
        m.start()
        results = test_all(m, proxies)
    finally:
        m.stop()
    if not results:
        raise SystemExit("没有任何节点通过真实校验，保持上一版订阅不动")
    stats = build_outputs(proxies, results)
    subprocess.run([sys.executable, os.path.join(HERE, "render_index.py")], cwd=HERE)
    if not args.no_push:
        push(stats)


def push(stats):
    log("\n推送结果回仓库…")
    def run(cmd):
        r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
        if r.returncode != 0:
            log(f"  [warn] {' '.join(cmd)} -> {r.stderr.strip()[:200]}")
        return r
    run(["git", "add", "dist"])
    d = run(["git", "diff", "--cached", "--quiet"])
    if d.returncode == 0:
        log("  没有变化，跳过提交")
        return
    run(["git", "commit", "-m",
         f"chore: 本机真实协议校验 {stats['alive']} 个可用节点 {time.strftime('%Y-%m-%d %H:%M')}"])
    # 定时任务跑的时候 CI 可能刚提交过，先 rebase 再推
    run(["git", "pull", "--rebase", "--autostash"])
    r = run(["git", "push"])
    if r.returncode != 0:
        run(["git", "pull", "--rebase", "--autostash"])
        r = run(["git", "push"])
    log("  已推送" if r.returncode == 0 else "  推送失败，请检查凭据")


if __name__ == "__main__":
    main()
