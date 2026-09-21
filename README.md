# 免费节点自动订阅（全流程在 GitHub Actions 上完成）

从 GitHub 上的公开来源搜集免费代理节点，**在 GitHub Runner 上用 mihomo 内核按真实协议端到端验证**，
只把确实能连通的节点做成订阅，每 6 小时自动更新。

**不需要本地电脑参与**：Windows 可以关机、不用登录、不用开 Karing、没有本地计划任务、不需要本地
Python 或 mihomo。

## 订阅地址（完整链接，可直接填进客户端）

首页：**https://jwqsir2-lang.github.io/free-nodes/**

| 用途 | 完整地址 |
|---|---|
| Clash / mihomo / Karing | `https://jwqsir2-lang.github.io/free-nodes/cn/clash.yaml` |
| 只要 HTTP / HTTPS 代理（Clash） | `https://jwqsir2-lang.github.io/free-nodes/cn/http.yaml` |
| sing-box 完整配置 | `https://jwqsir2-lang.github.io/free-nodes/cn/singbox.json` |
| HTTP 代理 outbounds 数组 | `https://jwqsir2-lang.github.io/free-nodes/cn/http-outbounds.json` |
| base64 订阅（v2rayN 等） | `https://jwqsir2-lang.github.io/free-nodes/cn/v2ray.txt` |
| HTTP 代理 ip:port 文本 | `https://jwqsir2-lang.github.io/free-nodes/cn/http.txt` |

国内打不开 `github.io` 时接镜像路径：

```
https://raw.githubusercontent.com/jwqsir2-lang/free-nodes/main/dist/
https://cdn.jsdelivr.net/gh/jwqsir2-lang/free-nodes@main/dist/
```

## 自动化流程

| 工作流 | 时间（北京时间） | 做什么 |
|---|---|---|
| `update.yml` 搜集候选节点 | 02:00 / 08:00 / 14:00 / 20:00 | 拉取固定源 + 自动搜寻新源，解析去重，产出 `dist/candidates.yaml`，部署 Pages |
| `verify.yml` 真实协议校验 | 02:30 / 08:30 / 14:30 / 20:30 | 下载 mihomo 内核 → 按真实协议校验 → 生成订阅 → 提交 → 部署 Pages |
| `deploy.yml` 部署订阅页 | push 到 `dist/**` 时 | 用仓库里的统计数据现算订阅页并部署 |

三个工作流共用 `concurrency.group: pages`，不会互相打断。

## 校验是怎么做的

```
verify.py（在 ubuntu-latest 上）
  1. 读取 dist/candidates.yaml（由搜集工作流产出；缺失则回退到远端拉取）
  2. 净化节点：按类型白名单剔除非法字段（mihomo 解析极严格，一个坏节点会让整份配置失败）
  3. 用 mihomo -t 当裁判，按报错里的下标逐个剔除它拒绝的节点
  4. UDP 出站探测：决定 hysteria2 / tuic 这类 QUIC 协议能不能测
  5. HTTP 代理展开「明文 / TLS 包装」两个变体，都真测，折叠时 TLS 优先
  6. 启动 mihomo，用 Clash API /proxies/<name>/delay 对每个节点发真实请求
     目标是被墙的 gstatic / google generate_204 —— 通了才收录
  7. 写 dist/cn/*（clash.yaml / http.yaml / singbox.json / http-outbounds.json / http.txt / v2ray.txt）
  8. 校验结构（节点数、分组引用完整性）后提交、部署
```

DNS 用 fake-ip，域名交给代理远端解析，避开本地 DNS 污染。

## 判定局限（必须知道）

校验跑在 **GitHub 的海外机器**上，所以它判定的是「**海外**能否连通」，这不等于「你那边能否连通」：

| 局限 | 说明 |
|---|---|
| **地理位置偏差（最大问题）** | 海外能通的节点在国内可能走不通。典型例子是被 Cloudflare 边缘接管的地址：海外连返回 204，国内连返回 `409` / `error code: 1001`。实测过一批被海外判为「可用」的 500 个节点，从国内重测只有 10 个能用。 |
| **反向漏报** | 部分节点只对特定地区开放或封禁海外 IP，海外机器测不通但国内能用 —— 这类会被本流程删掉。 |
| **SOCKS4 无法验证** | mihomo 与 sing-box 都**没有** SOCKS4 出站类型，实测报 `unsupport proxy type: socks4`。这类节点只能丢弃，本流程不做收录（`fetch_nodes.py` 里直接跳过 `socks4://`）。 |
| **UDP 协议（hysteria2 / tuic）** | 走 QUIC(UDP)，能否验证取决于 Runner 的 UDP 出站是否放行。脚本每次先探测，不可用时会跳过这两个协议，并在 `stats.json` 的 `udp_egress` / `skipped_protocols` 和订阅页上如实标注。 |
| **端口限制** | Runner 出站对个别端口有限制（例如 25/465/587 被云厂商封禁），落在这些端口的节点会测不通。 |
| **延迟数字** | 只是海外机器到节点的数值，不代表你在国内的实际速度。 |
| **协议覆盖** | 可真实握手验证：VMess / VLESS / Trojan / Shadowsocks / Hysteria2 / TUIC / HTTP(含 TLS) / SOCKS5。不可验证：SOCKS4（内核不支持）、SSR（内核不支持）。 |

**结论**：这份订阅表示「这些节点在海外连通性测试中确实活着」，能筛掉大量假节点和死节点，
但不能保证在国内可用。通过率通常在 2~3%。

## 文件

| 文件 | 作用 |
|---|---|
| `fetch_nodes.py` | 搜集、解析（vmess/vless/trojan/ss/hysteria2/tuic/http/socks5）、去重，产出候选 |
| `discover_sources.py` | 用 GitHub 搜索 API 自动搜寻新的节点源 |
| `verify.py` | 真实协议校验并生成全部订阅产物（Runner 与本地都能跑） |
| `render_index.py` | 生成订阅页（部署工作流调用） |
| `measure_cn.py` | 手动诊断工具：从**当前机器**直连测一批代理的真实可用性，仅在你主动运行时使用 |

## 手动跑一次（可选）

在仓库 Actions 页面选「真实协议校验（在 Runner 上完成）」→ Run workflow，可调 HTTP 测试上限与超时。

想在本地复核（可选，不参与自动化）：

```bash
pip install -r requirements.txt
# 把 mihomo 放到 tools/（Windows 用 mihomo.exe），或用 MIHOMO_BIN 指定路径
python verify.py --input dist/candidates.yaml --no-push
```

## 风险提示

免费公共节点由陌生人提供，**可能被记录、篡改或劫持流量**。不要用它登录银行、邮箱、公司账号等敏感服务，
只当临时通道用。节点存活期很短（几小时到几天），客户端里请把订阅设为自动更新。
