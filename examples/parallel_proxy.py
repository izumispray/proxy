"""
ZenProxy 本地客户端并行代理示例
通过 sing-box-zenproxy-client 本地客户端，并行使用 10 个不同 IP 访问 cn.bing.com
"""

import asyncio
import aiohttp
import json

# === 配置 ===
CLASH_API = "http://127.0.0.1:9090"
CLASH_SECRET = "your-secret"  # sing-box config.json 中的 secret
ZENPROXY_SERVER = "https://zenproxy.top"
ZENPROXY_API_KEY = "xxx"
PROXY_COUNT = 10
TARGET_URL = "https://cn.bing.com"


def headers():
    return {"Authorization": f"Bearer {CLASH_SECRET}", "Content-Type": "application/json"}


async def setup_proxies(session: aiohttp.ClientSession) -> list[dict]:
    """从 ZenProxy Server fetch 代理并批量创建绑定"""

    # 1. 从服务器 fetch 代理
    print(f"[1/3] 从 {ZENPROXY_SERVER} 获取 {PROXY_COUNT} 个代理...")
    async with session.post(
        f"{CLASH_API}/fetch",
        headers=headers(),
        json={
            "server": ZENPROXY_SERVER,
            "api_key": ZENPROXY_API_KEY,
            "count": PROXY_COUNT,
        },
    ) as resp:
        result = await resp.json()
        if resp.status != 200:
            raise Exception(f"Fetch 失败: {result}")
        print(f"     获取了 {result['added']} 个代理")

    # 2. 批量创建绑定 → 每个代理分配一个本地端口
    print(f"[2/3] 批量创建绑定...")
    async with session.post(
        f"{CLASH_API}/bindings/batch",
        headers=headers(),
        json={"all": True},
    ) as resp:
        result = await resp.json()
        if resp.status != 200:
            raise Exception(f"批量绑定失败: {result}")
        print(f"     创建了 {result['created']} 个绑定 (失败 {result.get('failed', 0)})")

    # 3. 获取绑定列表
    print(f"[3/3] 获取绑定端口映射...")
    async with session.get(f"{CLASH_API}/bindings", headers=headers()) as resp:
        bindings = await resp.json()
        print(f"     共 {len(bindings)} 个活跃绑定")
        for b in bindings[:PROXY_COUNT]:
            print(f"       ├── {b['tag'][:8]}... → 127.0.0.1:{b['listen_port']}")
        return bindings[:PROXY_COUNT]


async def request_via_proxy(
    session: aiohttp.ClientSession, proxy_url: str, index: int
) -> dict:
    """通过指定本地代理端口访问目标 URL"""
    try:
        async with session.get(
            TARGET_URL,
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=15),
            allow_redirects=True,
            ssl=False,
        ) as resp:
            status = resp.status
            # 读取部分 body 确认连通
            body = await resp.read()
            size = len(body)
            return {
                "index": index,
                "proxy": proxy_url,
                "status": status,
                "size": size,
                "success": True,
            }
    except Exception as e:
        return {
            "index": index,
            "proxy": proxy_url,
            "error": str(e),
            "success": False,
        }


async def parallel_requests(bindings: list[dict]):
    """并行通过 10 个不同代理访问目标"""
    print(f"\n{'='*60}")
    print(f"并行通过 {len(bindings)} 个代理请求 {TARGET_URL}")
    print(f"{'='*60}\n")

    # 不使用代理的 session（直接连本地端口）
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, binding in enumerate(bindings):
            port = binding["listen_port"]
            proxy_url = f"http://127.0.0.1:{port}"
            tasks.append(request_via_proxy(session, proxy_url, i))

        # 并行执行所有请求
        results = await asyncio.gather(*tasks)

    # 打印结果
    success_count = 0
    for r in results:
        if r["success"]:
            success_count += 1
            print(f"  [✓] 代理 #{r['index']} ({r['proxy']}) → HTTP {r['status']}, {r['size']} bytes")
        else:
            print(f"  [✗] 代理 #{r['index']} ({r['proxy']}) → {r['error']}")

    print(f"\n结果: {success_count}/{len(results)} 成功")


async def cleanup(session: aiohttp.ClientSession):
    """清理：删除所有绑定和存储的代理"""
    print("\n清理中...")
    async with session.delete(f"{CLASH_API}/bindings/all", headers=headers()) as resp:
        result = await resp.json()
        print(f"  删除 {result.get('removed', 0)} 个绑定")
    async with session.delete(f"{CLASH_API}/store", headers=headers()) as resp:
        result = await resp.json()
        print(f"  删除 {result.get('removed', 0)} 个代理")


async def main():
    async with aiohttp.ClientSession() as session:
        # 设置代理
        bindings = await setup_proxies(session)

        if not bindings:
            print("没有可用的绑定，退出")
            return

        # 并行请求
        await parallel_requests(bindings)

        # 清理（可选，注释掉则保留绑定供后续使用）
        # await cleanup(session)


if __name__ == "__main__":
    asyncio.run(main())
