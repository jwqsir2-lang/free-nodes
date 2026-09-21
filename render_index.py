#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成订阅页。

关键：页面上给出的必须是**完整 URL**。之前写的是相对路径（cn/clash.yaml），
复制出来粘到客户端根本打不开。
CI 和本机校验器都会通过部署工作流调用它。
"""
import json
import os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

REPO = os.environ.get("REPO", "jwqsir2-lang/free-nodes")
OWNER, NAME = REPO.split("/")
BASE = f"https://{OWNER}.github.io/{NAME}/"
MIRRORS = [
    f"https://raw.githubusercontent.com/{REPO}/main/dist/",
    f"https://cdn.jsdelivr.net/gh/{REPO}@main/dist/",
]

# (label, 文件, 说明)
FILES = [
    ("Clash / mihomo / Karing 订阅（全部）", "cn/clash.yaml", "全部已验证节点，客户端设自动更新即可"),
    ("只要 HTTP / HTTPS 代理（Clash）", "cn/http.yaml", "http 类型节点，字段与 clash.yaml 一致"),
    ("sing-box 完整配置（JSON）", "cn/singbox.json", "sing-box 内核只认整份配置，没有订阅机制；下载后用 -c 指定"),
    ("HTTP 代理 outbounds 数组（JSON）", "cn/http-outbounds.json", "贴进你已有的 sing-box 配置里"),
    ("HTTP 代理 ip:port 纯文本", "cn/http.txt", "只有主机端口，不含 TLS 参数"),
    ("base64 订阅（v2rayN / Shadowrocket）", "cn/v2ray.txt", "vmess / vless / trojan / ss / hysteria2"),
]


def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def card(label, fn, desc):
    url = BASE + fn
    mirrors = "".join(
        f"<div class='url sm' onclick=\"cp(this)\">{m}{fn}</div>" for m in MIRRORS)
    return f"""<div class='card'>
  <div class='fn'>{label}</div><div class='desc'>{desc}</div>
  <div class='url' onclick="cp(this)">{url}</div>
  <details><summary>国内打不开 github.io 时用镜像</summary>{mirrors}</details>
</div>"""


def main():
    cand = load(os.path.join(DIST, "stats.json"))
    cn = load(os.path.join(DIST, "cn", "stats.json"))
    big = cn["alive"] if cn else 0

    if cn and os.path.exists(os.path.join(DIST, "cn", "clash.yaml")):
        cards = "".join(card(*c) for c in FILES)
        sub = f"""
  <h2>订阅地址（点一下复制完整链接）</h2>
  <p class="ok">下面这些节点已在本机按真实协议、对着被墙目标端到端验证过，能通才收录。</p>
  {cards}
  <div class="meta">校验时间 {cn['verified_at']}　|　目标 {' / '.join(cn['test_targets'])}<br>
  候选 {cn['candidates']} → 可用 {cn['alive']}　|　HTTP 代理 {cn.get('http_total', 0)} 个（其中带 TLS {cn.get('http_tls', 0)} 个）</div>"""
    else:
        sub = f"""
  <h2>还没有可用订阅</h2>
  <div class="warn">本机校验（<code>verify_cn.py</code>）还没跑过，所以这里没有订阅地址。<br>
  候选名单已经准备好（{cand['candidates'] if cand else 0} 个），在本地跑一次
  <code>python verify_cn.py</code> 就会生成。</div>"""

    cand_block = ""
    if cand:
        rows = "".join(
            f"<tr><td>{s['name']}</td><td>{s['status']}</td><td class='r'>{s['count']}</td></tr>"
            for s in cand["sources"])
        cand_block = f"""
  <h2>候选来源</h2>
  <div class="meta">最近搜集 {cand['updated_utc8']}　|　候选 {cand['candidates']} 个</div>
  <table><tr><th>源</th><th>状态</th><th class="r">抓取</th></tr>{rows}</table>"""

    html = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>免费节点订阅 · 本机实测可用</title>
<style>
:root{{color-scheme:dark light}}
body{{font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:900px;
margin:0 auto;padding:26px 18px 60px;line-height:1.65}}
h1{{font-size:23px;margin:0 0 4px}}
h2{{font-size:16px;margin:26px 0 8px}}
.sub{{opacity:.65;font-size:14px}}
.ok{{font-size:13.5px;opacity:.8;margin:6px 0 14px}}
.card{{border:1px solid #8884;border-radius:12px;padding:13px 15px;margin:11px 0}}
.fn{{font-weight:600}}
.desc{{font-size:13px;opacity:.65;margin:2px 0 8px}}
.url{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:#8882;border-radius:8px;
padding:9px 11px;word-break:break-all;cursor:pointer}}
.url:hover{{background:#8883}}
.url.sm{{font-size:11.5px;opacity:.8;margin-top:5px}}
details{{margin-top:7px}} summary{{font-size:12.5px;opacity:.7;cursor:pointer}}
.meta{{font-size:12.5px;opacity:.7;margin:10px 0}}
table{{border-collapse:collapse;width:100%;font-size:13.5px;margin-top:6px}}
td,th{{border-bottom:1px solid #8883;padding:6px;text-align:left}}
th{{opacity:.6;font-weight:500}} .r{{text-align:right}}
.warn{{border-left:3px solid #e0a020;padding:10px 14px;background:#e0a0201a;border-radius:8px;font-size:13.5px}}
code{{background:#8882;padding:1px 5px;border-radius:5px;font-size:12.5px}}
</style></head><body>
<h1>免费节点订阅</h1>
<div class="sub">候选由 GitHub Actions 定时搜集，可用性由<b>本机按真实协议端到端实测</b>决定。</div>
{sub}
{cand_block}
<h2>关于 sing-box</h2>
<div class="warn">
sing-box <b>内核本身没有订阅/自动更新机制</b>，它只接受一份完整的 config 文件，所以不能像 Clash 那样填个
URL 就自动更新。上面给的 <code>cn/singbox.json</code> 是可直接 <code>sing-box check -c</code> 通过、
导入即用的完整配置；要自动更新就用支持订阅的客户端（Karing 等）订阅 <code>cn/clash.yaml</code>。
</div>
<h2>为什么要本机测</h2>
<div class="warn">
海外机器上判定的“可用”在国内基本无效（大量 Cloudflare 边缘 IP，国内连返回 409 / error 1001）。
所以 CI 只负责搜集候选，判定放在本地：用 mihomo 内核按真实协议打被墙目标，通了才收录。
HTTP 代理还会分别按「明文」和「TLS 包装」两种形态各测一遍，通过率通常在 2~3%。
</div>
<h2>注意</h2>
<div class="warn">
免费公共节点由陌生人提供，<b>可能被记录、篡改或劫持流量</b>。不要用它登录银行、邮箱、公司账号等敏感服务。
节点存活期很短，客户端里请把订阅设为自动更新。
</div>
<script>
function cp(e){{const t=e.textContent;navigator.clipboard.writeText(t.trim());
e.textContent='已复制 ✓';setTimeout(()=>e.textContent=t,900);}}
</script></body></html>"""

    os.makedirs(DIST, exist_ok=True)
    with open(os.path.join(DIST, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)
    print(f"已生成 {DIST}/index.html（可用节点 {big} 个，订阅地址为完整 URL）")


if __name__ == "__main__":
    main()
