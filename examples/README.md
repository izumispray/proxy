# ZenProxy 示例

本目录包含 ZenProxy 的使用示例，展示两种代理模式的典型用法。

## 前置条件

```bash
pip install aiohttp
```

## 两种模式对比

| | 本地客户端模式 | Relay 模式 |
|---|---|---|
| **需要 sing-box** | 是 | 否 |
| **请求路径** | 你 → 本地端口 → 代理节点 → 目标 | 你 → ZenProxy 服务器 → 代理节点 → 目标 |
| **适用场景** | 高并发、低延迟、需要精细控制 | 快速上手、无需部署客户端 |
| **并发能力** | 最高 10000 端口同时使用 | 受服务端并发限制 |
| **示例文件** | `parallel_proxy.py` / `rotating_proxy.py` | `parallel_relay.py` / `rotating_relay.py` |

---

## 文件说明

```
examples/
├── config.json          # sing-box 最小配置（本地客户端模式需要）
├── parallel_proxy.py    # 本地客户端 - 并行多 IP
├── rotating_proxy.py    # 本地客户端 - 轮换多 IP
├── parallel_relay.py    # Relay - 并行多 IP
└── rotating_relay.py    # Relay - 轮换多 IP
```

---

## 配置

所有示例顶部都有配置区域，修改后即可运行：

```python
# 本地客户端模式的配置
CLASH_API = "http://127.0.0.1:9090"       # sing-box Clash API 地址
CLASH_SECRET = "your-secret"               # config.json 中的 secret
ZENPROXY_SERVER = "https://zenproxy.top"   # ZenProxy 服务器地址
ZENPROXY_API_KEY = "your-api-key"          # 你的 API Key

# Relay 模式的配置
ZENPROXY_SERVER = "https://zenproxy.top"   # ZenProxy 服务器地址
ZENPROXY_API_KEY = "your-api-key"          # 你的 API Key
```

---

## 示例 1：parallel_proxy.py — 本地并行多 IP

**场景**：同时通过 10 个不同 IP 访问目标网站。

**流程**：

```
1. POST /fetch     — 从 ZenProxy 服务器获取 10 个代理节点
2. POST /bindings/batch — 批量创建本地端口绑定（每个代理分配一个本地端口）
3. GET  /bindings  — 获取端口映射列表
4. 并行通过 10 个本地端口发起请求，每个端口对应不同出口 IP
```

**架构图**：

```
                    ┌── 127.0.0.1:20001 ── 代理A (IP: 1.2.3.4) ──┐
                    ├── 127.0.0.1:20002 ── 代理B (IP: 5.6.7.8) ──┤
你的程序 ──并行──→  ├── 127.0.0.1:20003 ── 代理C (IP: 9.10.11.12)─┤──→ cn.bing.com
                    ├── ...                                        │
                    └── 127.0.0.1:20010 ── 代理J (IP: x.x.x.x) ──┘
```

**运行**：

```bash
# 先启动 sing-box 客户端
./zenproxy-client run -c config.json

# 另一个终端运行示例
python parallel_proxy.py
```

**输出示例**：

```
============================================================
并行通过 10 个代理请求 https://cn.bing.com
============================================================

  [✓] 代理 #0 (http://127.0.0.1:20001) → HTTP 200, 12345 bytes
  [✓] 代理 #1 (http://127.0.0.1:20002) → HTTP 200, 12301 bytes
  ...
  [✓] 代理 #9 (http://127.0.0.1:20010) → HTTP 200, 12288 bytes

结果: 10/10 成功
```

---

## 示例 2：rotating_proxy.py — 本地轮换多 IP

**场景**：100 次请求，每批 10 个并行，每批使用不同的代理 IP。适合批量注册、数据采集等需要大量不同 IP 的场景。

**流程**：

```
1. 清理旧数据（DELETE /bindings/all + DELETE /store）
2. POST /fetch — 一次性获取 100 个代理
3. 循环 10 批，每批：
   a. 取 10 个代理 → POST /bindings/batch 创建绑定
   b. 并行通过 10 个端口发起请求
   c. DELETE /bindings/{tag} 删除绑定，释放端口
4. 最终汇总统计
```

**架构图**：

```
批次1: 代理 1-10  → 绑定端口 → 并行请求 → 释放端口
批次2: 代理 11-20 → 绑定端口 → 并行请求 → 释放端口
批次3: 代理 21-30 → 绑定端口 → 并行请求 → 释放端口
...
批次10: 代理 91-100 → 绑定端口 → 并行请求 → 释放端口

→ 100 次请求，100 个不同 IP
```

**运行**：

```bash
python rotating_proxy.py
```

**输出示例**：

```
============================================================
  轮换代理示例
  目标: https://cn.bing.com
  总请求: 100, 每批并行: 10, 共 10 批
  每批使用不同的代理 IP
============================================================

[准备] 从 https://zenproxy.top 获取 100 个代理...
       已获取 100 个代理

  批次  1/10: 10 成功, 0 失败  (请求 #1-#10)
  批次  2/10: 10 成功, 0 失败  (请求 #11-#20)
  ...
  批次 10/10: 10 成功, 0 失败  (请求 #91-#100)

============================================================
  完成! 耗时 25.3s
  总计: 100 成功, 0 失败 / 100 请求
  平均: 253ms/请求 (含绑定开销)
  使用了 100 个不同 IP
============================================================
```

**注意**：该脚本开头会执行 `cleanup()` 清理旧数据，因此可以在 `parallel_proxy.py` 之后直接运行，无需重启 sing-box。

---

## 示例 3：parallel_relay.py — Relay 并行多 IP

**场景**：无需部署本地客户端，直接通过服务端 Relay 端点并行使用 10 个不同代理。

**流程**：

```
1. 并行发送 10 个请求到 /api/relay?api_key=xxx&url=https://cn.bing.com
2. 服务端为每个请求随机分配不同代理转发
3. 响应头中包含代理信息（X-Proxy-IP, X-Proxy-Country, X-Proxy-Name）
```

**架构图**：

```
                                          ┌── 代理A ──┐
你的程序 ──10个请求──→ ZenProxy 服务器 ──→├── 代理B ──┤──→ cn.bing.com
                                          ├── ...     │
                                          └── 代理J ──┘
```

**运行**：

```bash
# 不需要 sing-box，直接运行
python parallel_relay.py
```

**输出示例**：

```
============================================================
  Relay 并行示例
  目标: https://cn.bing.com
  并行: 10 个请求，每个走不同代理
============================================================

  [✓] # 0  203.0.113.1      US  HTTP 200  12345 bytes
  [✓] # 1  198.51.100.2     JP  HTTP 200  12301 bytes
  ...
  [✓] # 9  192.0.2.10       HK  HTTP 200  12288 bytes

结果: 10/10 成功
```

---

## 示例 4：rotating_relay.py — Relay 轮换多 IP

**场景**：无需本地客户端，通过 Relay 端点完成 100 次请求，每批 10 个并行。

**流程**：

```
1. 循环 10 批，每批并行发送 10 个请求到 /api/relay
2. 服务端自动为每个请求分配不同代理
3. 统计去重 IP 数量
```

**运行**：

```bash
python rotating_relay.py
```

**输出示例**：

```
============================================================
  Relay 轮换示例
  目标: https://cn.bing.com
  总请求: 100, 每批并行: 10, 共 10 批
============================================================

  批次  1/10: 10 成功, 0 失败  (请求 #1-#10)  IP: 1.2.3.4, 5.6.7.8, ...
  批次  2/10: 10 成功, 0 失败  (请求 #11-#20)  IP: 9.10.11.12, ...
  ...
  批次 10/10: 10 成功, 0 失败  (请求 #91-#100) IP: ...

============================================================
  完成! 耗时 18.2s
  总计: 100 成功, 0 失败 / 100 请求
  去重 IP 数: 87
  平均: 182ms/请求
============================================================
```

---

## config.json — sing-box 最小配置

本地客户端模式需要先启动 sing-box，使用此最小配置即可：

```json
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "your-secret"
    }
  },
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
```

- `external_controller`：Clash API 监听地址，脚本中的 `CLASH_API` 需与此一致
- `secret`：API 认证密钥，脚本中的 `CLASH_SECRET` 需与此一致
- 代理 outbound 会在运行时通过 API 动态创建，无需预先配置

---

## 如何选择？

**推荐 Relay 模式**（`parallel_relay.py` / `rotating_relay.py`），如果：
- 只需简单使用，不想部署客户端
- 请求量不大（几百次以内）
- 不需要保持长连接

**推荐本地客户端模式**（`parallel_proxy.py` / `rotating_proxy.py`），如果：
- 需要高并发（数千并发连接）
- 需要更低延迟（少一跳）
- 需要精细控制每个代理的生命周期
- 需要 SOCKS5 代理（Relay 只支持 HTTP）

## 常见问题

**Q: 两个脚本能连续运行吗？**

A: 可以。`rotating_proxy.py` 开头会自动清理旧数据，所以运行完 `parallel_proxy.py` 后可以直接运行 `rotating_proxy.py`，无需重启 sing-box。

**Q: 如何修改并发数和总请求数？**

A: 修改脚本顶部的配置：
```python
BATCH_SIZE = 10       # 每批并发数
TOTAL_REQUESTS = 100  # 总请求数（rotating 模式）
PROXY_COUNT = 10      # 并发代理数（parallel 模式）
```

**Q: 如何筛选特定国家/地区的代理？**

A: 本地客户端模式在 `POST /fetch` 请求中添加筛选参数：
```python
json={
    "server": ZENPROXY_SERVER,
    "api_key": ZENPROXY_API_KEY,
    "count": 10,
    "country": "US",      # 筛选美国代理
    "chatgpt": True,      # 筛选支持 ChatGPT 的代理
    "type": "vmess",      # 筛选 vmess 类型
}
```

Relay 模式在 URL 参数中添加：
```
/api/relay?api_key=xxx&url=target&country=US&chatgpt=true
```
