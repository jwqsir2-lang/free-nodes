#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动搜寻新的节点源
--------------------------------------------------
用 GitHub 搜索 API 找最近更新过的、可能存放免费节点的仓库，
再探测这些仓库里常见的订阅文件路径，命中就记进 discovered_sources.json。
旧记录每轮都会重新探测，失效的自动剔除。
"""
import concurrent.futures as cf
import json
import os
import re
import time
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

STORE = os.environ.get("DISCOVERED", "discovered_sources.json")
MAX_DISCOVERED = int(os.environ.get("MAX_DISCOVERED", "25"))

QUERIES = [
    "免费节点 in:name,description,readme pushed:>{}",
    "free v2ray nodes in:name,description pushed:>{}",
    "clash 订阅 in:name,description,readme pushed:>{}",
    "free proxy list in:name,description pushed:>{}",
]

# 候选文件路径，按常见程度排序
CANDIDATE_PATHS = [
    "clash.yaml", "clash.yml", "sub", "v2ray.txt", "list.txt", "nodes.txt",
    "all.txt", "sub/sub.txt", "dist/clash.yaml", "output/clash.yaml",
    "dist/sub.txt", "proxies/all/data.txt", "http.txt",
]

# 已经手工维护在 fetch_nodes.py 里的源，不需要再"发现"
KNOWN_MARKERS = (
    "anaer/sub", "ermaozi/get_subscribe", "peasoft/nomorewalls", "mahdibland/shadowsocksaggregator",
    "freefq/free", "pawdroid/free-servers", "ripaojiedian/freenode", "barabama/freenodes",
    "proxifly/free-proxy-list", "thespeedx/proxy-list", "monosans/proxy-list",
)


def http_get(url, timeout=30, headers=None, method="GET"):
    h = {"User-Agent": UA, "Accept": "application/json, */*"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h, method=method)
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    opener = (urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
              if proxy else urllib.request.build_opener())
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore"), dict(r.headers)


def gh_headers():
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def search_repos(days=30):
    since = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
    found = {}
    for q in QUERIES:
        url = ("https://api.github.com/search/repositories?q="
               + urllib.parse.quote(q.format(since))
               + "&sort=updated&order=desc&per_page=12")
        try:
            body, _ = http_get(url, headers=gh_headers())
            data = json.loads(body)
        except Exception as e:
            print(f"  [warn] 搜索失败 {q[:32]}… {str(e)[:60]}", flush=True)
            continue
        for it in data.get("items", []):
            full = it.get("full_name", "")
            if full and full.lower() not in KNOWN_MARKERS:
                found[full] = it.get("default_branch") or "main"
        time.sleep(1)
    return found


def probe(full, branch, path):
    url = f"https://raw.githubusercontent.com/{full}/{branch}/{path}"
    try:
        body, hdr = http_get(url, timeout=25, method="GET")
    except Exception:
        return None
    if len(body) < 800:
        return None
    head = body[:4000]
    looks_like_nodes = bool(
        re.search(r"(vmess|vless|trojan|ss|hysteria2?|tuic)://", body)
        or "proxies:" in head
        or re.match(r"^\s*(?:\d{1,3}\.){3}\d{1,3}:\d+", body)
    )
    if not looks_like_nodes:
        return None
    return {"name": f"{full.split('/')[-1]}/{path}", "url": url, "fmt": "auto",
            "from": full, "found_at": time.strftime("%Y-%m-%d")}


def load_store():
    if os.path.exists(STORE):
        try:
            with open(STORE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def main():
    print("Step A: 搜索 GitHub 上最近更新的候选仓库…", flush=True)
    repos = search_repos()
    print(f"  候选仓库 {len(repos)} 个", flush=True)

    # 老记录也重新探测一遍，失效的剔除
    old = load_store()
    old_repos = {r["from"]: None for r in old if r.get("from")}
    for r in old_repos:
        if r in repos:
            continue
        try:
            body, _ = http_get(f"https://api.github.com/repos/{r}", headers=gh_headers())
            repos[r] = json.loads(body).get("default_branch") or "main"
        except Exception:
            pass
    print(f"  含历史记录共 {len(repos)} 个待探测", flush=True)

    print("Step B: 探测常见订阅文件路径…", flush=True)
    jobs = [(full, br, p) for full, br in repos.items() for p in CANDIDATE_PATHS]
    hits = []
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(probe, f, b, p): (f, p) for f, b, p in jobs}
        for fu in cf.as_completed(futs):
            try:
                r = fu.result()
            except Exception:
                r = None
            if r:
                print(f"  [命中] {r['url']}", flush=True)
                hits.append(r)

    # 每个仓库最多留 2 个文件，总量封顶
    per_repo, kept = {}, []
    for h in sorted(hits, key=lambda x: x["url"]):
        per_repo[h["from"]] = per_repo.get(h["from"], 0) + 1
        if per_repo[h["from"]] <= 2 and len(kept) < MAX_DISCOVERED:
            kept.append(h)

    with open(STORE, "w", encoding="utf-8") as f:
        json.dump(kept, f, ensure_ascii=False, indent=2)
    print(f"Step C: 写入 {STORE}，共 {len(kept)} 个自动发现的源", flush=True)


if __name__ == "__main__":
    main()
