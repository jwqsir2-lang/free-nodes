# 免费节点自动订阅

自动从 GitHub 上的公开来源搜集免费代理节点，检测存活，生成可直接订阅的配置，每 6 小时刷新一次。

## 怎么用

订阅地址（把 `<你的用户名>` 换成实际账号）：

| 文件 | 用途 | 地址 |
|---|---|---|
| `clash.yaml` | Clash / mihomo / Clash Meta / Karing / Clash Verge | `https://<你的用户名>.github.io/free-nodes/clash.yaml` |
| `http.yaml` | 只要 HTTP 代理的 Clash 配置 | `https://<你的用户名>.github.io/free-nodes/http.yaml` |
| `http.txt` | 纯 `ip:port` 文本（HTTP 代理） | `https://<你的用户名>.github.io/free-nodes/http.txt` |
| `v2ray.txt` | base64 订阅（v2rayN / Shadowrocket 等） | `https://<你的用户名>.github.io/free-nodes/v2ray.txt` |

打开 `https://<你的用户名>.github.io/free-nodes/` 有带复制按钮的订阅页。

国内如果 `github.io` 连不上，可以换这两个镜像地址：

```
https://raw.githubusercontent.com/<你的用户名>/free-nodes/main/dist/clash.yaml
https://cdn.jsdelivr.net/gh/<你的用户名>/free-nodes@main/dist/clash.yaml
```

在客户端里把订阅设为**自动更新**（间隔 6 小时以上）即可。

## 它是怎么工作的

```
GitHub Actions（每 6 小时 / 手动触发）
  ├─ discover_sources.py   用 GitHub 搜索 API 找最近活跃的节点仓库，
  │                        探测常见订阅路径，命中的记进 discovered_sources.json
  ├─ fetch_nodes.py
  │     拉取 11 个固定源 + 自动发现的源
  │     解析 vmess / vless / trojan / ss / hysteria2 / tuic / http / socks5
  │     过滤非公网地址（源里混了不少 127.0.0.53 这类假节点）
  │     去重 → 300 线程并发 TCP 连通性 + 延迟检测
  │     HTTP 代理额外做一次真实请求验证（GET generate_204）
  │     排序（HTTP 优先）→ 生成 dist/ 下所有订阅文件
  ├─ 结构校验（节点数、分组引用完整性）
  ├─ 提交回仓库
  └─ 部署到 GitHub Pages
```

HTTP 代理由用户在需求里指定优先，所以在排序和分组里都排在前面。

## 本地手动跑

```bash
pip install -r requirements.txt
export GITHUB_TOKEN=$(gh auth token)   # 可选，不加会被搜索 API 限流
python discover_sources.py             # 可选：搜寻新源
python fetch_nodes.py                  # 生成 dist/
```

可用环境变量调参：`MAX_PER_SOURCE`（每源最多取几条，默认 1500）、`MAX_TOTAL_TEST`（最多测几个，默认 9000）、`TCP_TIMEOUT`（默认 3 秒）、`HTTP_FUNC_LIMIT`（对多少个 HTTP 代理做真实请求验证，默认 400）。

## 加自己的源

编辑 `fetch_nodes.py` 顶部的 `SOURCES` 列表，`fmt` 取值：`auto`（自动判断）/ `clash`（Clash 配置）/ `iplist`（`ip:port` 列表）。
另外在 `discover_sources.py` 的 `KNOWN_MARKERS` 里加上域名片段，避免自动搜寻重复收录。

## 局限与风险（请务必读一下）

- **免费公共节点是陌生人提供的，可能记录、篡改、劫持你的流量。** 不要用来登录银行、邮箱、公司后台等敏感账号，只当临时通道用。
- **存活率天生很低。** 公共节点通常几小时就失效或被打爆，所以订阅要设成自动更新。
- 存活检测是 **TCP 连通性**（外加 HTTP 代理的一次真实请求）。vmess/vless/ss 这些协议用 Python 没法完整握手验证，所以「能连上」不等于「一定能用」，可能有一部分在客户端里仍连不通。
- 检测跑在 **GitHub 的海外机器**上，判断的是「海外能否连通」，不等于「中国能否连通」。海外通、国内不通的节点会被保留下来。
- GitHub Actions 的 `schedule` 在高峰期可能延迟几分钟到几十分钟，不是精确的 6 小时。
- 本仓库所有节点信息都是公开的，任何人都能用这个订阅地址。
