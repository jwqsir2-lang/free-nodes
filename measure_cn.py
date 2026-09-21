#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从本机(国内)直连实测一批 HTTP 代理：分别打被墙目标和中立目标"""
import concurrent.futures as cf
import re
import socket
import sys
import urllib.parse

TARGETS = {
    "google(被墙)": "http://www.google.com/generate_204",
    "gstatic(被墙)": "http://www.gstatic.com/generate_204",
    "baidu(中立)": "http://www.baidu.com/",
}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"


def tcp(host, port, t=5):
    try:
        s = socket.create_connection((host, port), timeout=t)
        s.close()
        return True
    except Exception:
        return False


def via(host, port, url, t=8):
    u = urllib.parse.urlsplit(url)
    try:
        s = socket.create_connection((host, port), timeout=t)
        s.settimeout(t)
        s.sendall((f"GET {url} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: {UA}\r\n"
                   f"Proxy-Connection: close\r\nConnection: close\r\n\r\n").encode())
        head = b""
        while len(head) < 512:
            b = s.recv(512)
            if not b:
                break
            head += b
            if b"\r\n\r\n" in head:
                break
        s.close()
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return int(m.group(1)) if m else -1
    except Exception:
        return 0


def main(path):
    lines = [l.strip() for l in open(path, encoding="utf-8") if l.strip()]
    print(f"待测 {len(lines)} 个 HTTP 代理（从本机直连，不走系统代理）\n")
    results = []
    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        futs = {}
        for l in lines:
            host, _, port = l.rpartition(":")
            futs[ex.submit(tcp, host, int(port))] = (host, int(port))
        alive = [futs[f] for f in cf.as_completed(futs) if f.result()]
    print(f"1) TCP 能连上代理端口：{len(alive)}/{len(lines)}")

    codes = {k: {} for k in TARGETS}
    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        for tname, url in TARGETS.items():
            futs = [ex.submit(via, h, p, url) for h, p in alive]
            for f in cf.as_completed(futs):
                c = f.result()
                codes[tname][c] = codes[tname].get(c, 0) + 1
    print("\n2) 通过代理发真实请求，返回的 HTTP 状态码分布：")
    for tname in TARGETS:
        ok = codes[tname].get(204, 0) + codes[tname].get(200, 0)
        print(f"   {tname:16} 成功 {ok:>4} / {len(alive)}   " +
              "  ".join(f"{k}→{v}" for k, v in sorted(codes[tname].items())))
    return codes


if __name__ == "__main__":
    main(sys.argv[1])
