#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成订阅页面。CI 和本机校验器都会调用它，两边的数据谁有就渲染谁。"""
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")


def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def main():
    cand = load(os.path.join(DIST, "stats.json"))
    cn = load(os.path.join(DIST, "cn", "stats.json"))
    big = cn["alive"] if cn else 0

    if cn:
        sub = f"""
  <h2>订阅地址（点一下复制）</h2>
  <p class="ok">下面这些节点已在本机按真实协议、对着被墙目标端到端验证过，能通才收录。</p>
  {card("Clash / mihomo / Karing 订阅（全部）", "cn/clash.yaml", f"{cn['alive']} 个已验证可用节点")}
  {card("只要 HTTP / HTTPS 代理（Clash）", "cn/http.yaml", f"{cn.get('http_total', 0)} 个，其中带 TLS 的 {cn.get('http_tls', 0)} 个；字段与 clash.yaml 完全一致")}
  {card("HTTP 代理 outbounds（sing-box / Karing JSON）", "cn/http-outbounds.json", f"{cn.get('http_total', 0)} 条 outbound，与客户端导出的条目同构")}
  {card("HTTP 代理 ip:port 纯文本", "cn/http.txt", "只给主机端口，不含 TLS 等参数")}
  {card("base64 订阅（v2rayN 等）", "cn/v2ray.txt", "vmess / vless / trojan / ss / hysteria2")}
  <div class="meta">校验时间 {cn['verified_at']}　|　校验目标 {' / '.join(cn['test_targets'])}<br>
  候选 {cn['candidates']} 个 → 可用 {cn['alive']} 个（{cn['alive'] * 100 // max(cn['candidates'], 1)}%）　|　{proto(cn['counts'])}</div>"""
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
  <div class="meta">最近搜集 {cand['updated_utc8']}　|　候选 {cand['candidates']} 个　|　{proto(cand['counts'])}</div>
  <table><tr><th>源</th><th>状态</th><th class="r">抓取</th></tr>{rows}</table>"""

    html = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>免费节点订阅 · 本机实测可用</title>
<style>
:root{{color-scheme:dark light}}
body{{font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:880px;
margin:0 auto;padding:28px 18px 60px;line-height:1.65}}
h1{{font-size:23px;margin:0 0 4px}}
h2{{font-size:16px;margin:26px 0 8px}}
.sub{{opacity:.65;font-size:14px}}
.ok{{font-size:13.5px;opacity:.8;margin:6px 0 14px}}
.pill{{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:1px 11px;
margin:3px 6px 3px 0;font-size:12.5px;opacity:.85}}
.card{{border:1px solid #8884;border-radius:12px;padding:13px 15px;margin:10px 0}}
.fn{{font-weight:600}}
.desc{{font-size:13px;opacity:.65;margin:2px 0 8px}}
.url{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:#8882;border-radius:8px;
padding:9px 11px;word-break:break-all;cursor:pointer}}
.url:hover{{background:#8883}}
.meta{{font-size:12.5px;opacity:.7;margin:10px 0}}
table{{border-collapse:collapse;width:100%;font-size:13.5px;margin-top:6px}}
td,th{{border-bottom:1px solid #8883;padding:6px;text-align:left}}
th{{opacity:.6;font-weight:500}}
.r{{text-align:right}}
.warn{{border-left:3px solid #e0a020;padding:10px 14px;background:#e0a0201a;border-radius:8px;font-size:13.5px}}
code{{background:#8882;padding:1px 5px;border-radius:5px;font-size:12.5px}}
</style></head><body>
<h1>免费节点订阅</h1>
<div class="sub">候选由 GitHub Actions 定时搜集，可用性由<b>本机按真实协议端到端实测</b>决定。</div>
{sub}
{cand_block}
<h2>为什么要本机测</h2>
<div class="warn">
之前一版在 GitHub 的海外机器上测存活，结果大量从美国能通、从国内根本走不通的节点（多为
Cloudflare 边缘 IP，国内连会返回 409 / error 1001）也被写进订阅。所以现在改成：CI 只负责搜集候选，
真正的判定放在本地，用 mihomo 内核按真实协议打被墙目标，通了才收录。
实测通过率通常在 2% 左右，这是正常水平。
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
    print(f"已生成 {DIST}/index.html（可用节点 {big if cn else 0} 个）")


def card(label, fn, desc):
    return (f"<div class='card'><div class='fn'>{label}</div><div class='desc'>{desc}</div>"
            f"<div class='url' onclick=\"cp(this)\">{fn}</div></div>")


def proto(counts):
    items = counts.items() if isinstance(counts, dict) else counts
    return "".join(f"<span class='pill'>{k} <b>{v}</b></span>" for k, v in
                   sorted(items, key=lambda kv: -kv[1]))


if __name__ == "__main__":
    main()
