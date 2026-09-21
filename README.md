# 免费节点自动订阅（本机实测可用）

从 GitHub 上的公开来源搜集免费代理节点，**在本机按真实协议端到端验证**，只把确实能穿透的节点做成订阅，
每 6 小时自动更新一次。

## 订阅地址

打开订阅页（带一键复制）：**https://jwqsir2-lang.github.io/free-nodes/**

| 用途 | 路径 |
|---|---|
| Clash / mihomo / Karing / Clash Verge | `cn/clash.yaml` |
| 只要 HTTP 代理（`ip:port` 文本） | `cn/http.txt` |
| v2rayN / Shadowrocket 等 base64 订阅 | `cn/v2ray.txt` |

拼上 `https://jwqsir2-lang.github.io/free-nodes/` 即为完整地址。国内打不开 `github.io` 时用镜像：

```
https://raw.githubusercontent.com/jwqsir2-lang/free-nodes/main/dist/cn/clash.yaml
https://cdn.jsdelivr.net/gh/jwqsir2-lang/free-nodes@main/dist/cn/clash.yaml
```

客户端里把订阅设成自动更新（间隔 ≥6 小时）。

## 为什么判定要在本机做

第一版把存活检测放在 GitHub 的海外机器上，结果是**从美国能通、从国内根本走不通**的节点也进了订阅
（大量 Cloudflare 边缘 IP，国内连会返回 `409` / `error 1001`）。

实测对比：同一批被海外判定为「可用」的 500 个节点，从国内按真实协议重测，**只有 10 个能用，HTTP 代理 0 个**。

所以现在的职责划分是：

```
GitHub Actions（每 6 小时，海外机器）
  ├─ discover_sources.py   用 GitHub 搜索 API 找最近活跃的节点仓库，探测常见订阅路径
  ├─ fetch_nodes.py        拉取固定源 + 自动发现的源，解析、过滤、去重
  └─ 输出 dist/candidates.yaml（全量候选，不做可用性判定）+ 订阅页
        ↓
本机（国内，定时任务）
  └─ verify_cn.py
       1. 净化节点：按类型白名单剔除非法字段（mihomo 解析极严格，一个坏节点会让整份配置失败）
       2. 让 mihomo 自己当裁判（-t），按报错下标逐个剔除它拒绝的节点
       3. 启动 mihomo，通过 Clash API /proxies/<name>/delay 对每个节点发**真实请求**
          目标是被墙的 gstatic / google generate_204 —— 通了才收录
       4. 只写通过的节点到 dist/cn/*，然后 git push 回去
```

DNS 用 fake-ip，域名交给代理远端解析，绕开本地 DNS 污染（`www.gstatic.com` 在污染下会被解析到国内 IP）。
mihomo 子进程会剥离 `HTTP_PROXY` 等环境变量，确保是直连拨号，不会误走系统代理。

## 文件

| 文件 | 作用 |
|---|---|
| `fetch_nodes.py` | 搜集、解析（vmess/vless/trojan/ss/hysteria2/tuic/http/socks5）、去重，产出候选 |
| `discover_sources.py` | 自动搜寻新的节点源，结果写入 `discovered_sources.json` |
| `verify_cn.py` | 本机真实协议校验，产出订阅，并推回仓库 |
| `render_index.py` | 生成订阅页，CI 与本地校验器共用 |
| `run_verify.bat` | 本地定时任务调用的入口 |
| `tools/mihomo.exe` | 代理内核，本机校验用（未纳入版本库，需自行下载） |

## 本地手动跑

```bash
pip install -r requirements.txt
# 下载 mihomo 内核到 tools/mihomo.exe（MetaCubeX/mihomo releases，windows-amd64-compatible）
python verify_cn.py                    # 拉远端候选并校验，成功后自动 push
python verify_cn.py --input x.yaml --no-push    # 用本地候选、不推送
python verify_cn.py --http-limit 2000  # HTTP 代理只测前 N 个（通过率极低，全测浪费）
```

可用环境变量：`DELAY_TIMEOUT_MS`（默认 5000）、`CONCURRENCY`（默认 96）、`LIMIT`、`HTTP_LIMIT`。

## 定时任务

```
schtasks /Query  /TN "FreeNodes-CN-Verify"          # 查看
schtasks /Run    /TN "FreeNodes-CN-Verify"          # 立刻跑一次
schtasks /Delete /TN "FreeNodes-CN-Verify" /F       # 删除
```

任务每 6 小时执行 `run_verify.bat`，日志追加到 `verify.log`。**前提是本机的代理软件开着**
（抓候选名单和 git push 需要 `127.0.0.1:3067`）。

## 通过率与局限

- 实测通过率约 **2%**：12436 个候选里通常只有两三百个真能穿透，这是免费公共节点的正常水平。
- **HTTP 代理基本不能用来翻墙。** 明文代理会把目标域名暴露给中间设备，且现在清单里大量是
  Cloudflare 边缘 IP，国内连直接 409。所以排序上虽然仍把 HTTP 放前面（按需求），但别指望它。
- 节点存活期很短，几小时到几天，必须靠自动更新。
- 校验用的是 TCP 之上的真实协议握手（vless/vmess/trojan/ss/hysteria2 由 mihomo 完成），
  等同于客户端的行为，但通过校验也不代表在另一条宽带、另一个时段一定成功。
- 单次校验要遍历几千个节点，约 3~6 分钟。

## 风险提示

免费公共节点由陌生人提供，**可能被记录、篡改或劫持流量**。不要用它登录银行、邮箱、公司账号等敏感服务，
只当临时通道用。
