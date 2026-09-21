# 免费节点自动订阅（本机实测可用）

从 GitHub 上的公开来源搜集免费代理节点，**在本机按真实协议端到端验证**，只把确实能穿透的节点做成订阅，
每 6 小时自动更新一次。

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

国内打不开 `github.io` 时，把路径接到这两个镜像后面：

```
https://raw.githubusercontent.com/jwqsir2-lang/free-nodes/main/dist/
https://cdn.jsdelivr.net/gh/jwqsir2-lang/free-nodes@main/dist/
```

例如 `https://cdn.jsdelivr.net/gh/jwqsir2-lang/free-nodes@main/dist/cn/clash.yaml`

## 关于 sing-box（重要）

**sing-box 内核没有订阅/自动更新机制**，它只接受一份完整 config 文件。所以：

- `cn/singbox.json` 是**可直接用的完整配置**（含 inbounds / outbounds / selector / route），
  验证方式：`sing-box check -c singbox.json`，启动：`sing-box run -c singbox.json`。
- 裸数组 `cn/http-outbounds.json` 只是给你贴进已有配置的 outbounds 片段。
- **想要订阅自动更新，就用支持订阅的客户端**（Karing、Clash Verge 等），订阅 `cn/clash.yaml`。

## HTTP 代理的两种形态

同一个 `host:port` 可能是：

- **明文**：客户端直接对它发 `CONNECT` → Clash 里 `type: http`，无 `tls` 字段
- **TLS 包装**：先和代理本身做 TLS 握手再发 `CONNECT` → `type: http` + `tls: true` + `servername`，
  对应 sing-box 的 `"tls": {"enabled": true, "server_name": ..., "insecure": true}`

节点列表**不会标**是哪一种，所以本机校验会给每个 http 候选生成两个变体都真测一遍，
折叠时 TLS 优先。输出的 `tls` 字段是测出来的，不是按端口猜的。

## 它是怎么工作的

```
GitHub Actions（每 6 小时，海外机器）
  ├─ discover_sources.py   用 GitHub 搜索 API 找最近活跃的节点仓库，探测常见订阅路径
  ├─ fetch_nodes.py        拉取固定源 + 自动发现的源，解析、过滤、去重
  └─ 产出 dist/candidates.yaml（全量候选，不做可用性判定）
        ↓
本机（国内，计划任务 FreeNodes-CN-Verify）
  └─ verify_cn.py
       1. 净化节点（mihomo 解析极严格，一个坏节点会让整份配置失败）
       2. 用 mihomo -t 当裁判，按报错下标逐个剔除它拒绝的节点
       3. 启动 mihomo，通过 /proxies/<name>/delay 对每个节点发真实请求，
          目标是被墙的 gstatic/google generate_204 —— 通了才收录
       4. HTTP 代理额外测「明文 / TLS」两个变体
       5. 写 dist/cn/* 并 push 回去
        ↓
部署工作流（push 到 dist/** 时触发）
  └─ 用仓库里的 dist/stats.json + dist/cn/stats.json 现算订阅页并部署 Pages
```

DNS 用 fake-ip，域名交给代理远端解析，绕开本地 DNS 污染。mihomo 子进程会剥离 `HTTP_PROXY` 等
环境变量，确保是直连拨号，不会误走系统代理。

## 文件

| 文件 | 作用 |
|---|---|
| `fetch_nodes.py` | 搜集、解析（vmess/vless/trojan/ss/hysteria2/tuic/http/socks5）、去重，产出候选 |
| `discover_sources.py` | 自动搜寻新的节点源 |
| `verify_cn.py` | 本机真实协议校验，产出订阅，并推回仓库 |
| `render_index.py` | 生成订阅页（CI 部署时调用，本机不写这个文件以避开提交冲突） |
| `run_verify.bat` | 本地计划任务入口 |
| `tools/mihomo.exe` | Clash 内核，本机校验用（未纳入版本库，需自行下载） |
| `tools/sing-box.exe` | 仅用于校验 `singbox.json` 合法性 |

## 本地手动跑

```bash
pip install -r requirements.txt
python verify_cn.py                     # 拉远端候选并校验，成功后自动 push
python verify_cn.py --input x.yaml --no-push
python verify_cn.py --http-limit 3000   # http 候选最多测多少个（会展开成 2 个变体）
```

环境变量：`DELAY_TIMEOUT_MS`（默认 5000）、`CONCURRENCY`（默认 96）、`LIMIT`、`HTTP_LIMIT`。

## 定时任务

```
schtasks /Query  /TN "FreeNodes-CN-Verify"      # 查看
schtasks /Run    /TN "FreeNodes-CN-Verify"      # 立刻跑一次
schtasks /Delete /TN "FreeNodes-CN-Verify" /F   # 删除
```

每 6 小时执行 `run_verify.bat`，日志追加到 `verify.log`。**前提是本机的代理软件开着**
（抓候选名单和 git push 需要 `127.0.0.1:3067`）。

## 通过率与局限

- 真实通过率约 **2~3%**，一万多个候选里通常只有三四百个真能穿透，这是免费公共节点的正常水平。
- 节点存活期很短，10 分钟就掉两成左右，必须靠自动更新。
- 校验用的是真实协议握手（由 mihomo 完成），等同于客户端行为；但通过校验也不代表在另一条宽带、
  另一个时段一定成功。
- HTTP 明文代理只能隧道 HTTPS 目标，自身不做任何加密，中间设备能看到你访问的域名。

## 风险提示

免费公共节点由陌生人提供，**可能被记录、篡改或劫持流量**。不要用它登录银行、邮箱、公司账号等敏感服务，
只当临时通道用。
