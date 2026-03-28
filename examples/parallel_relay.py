"""
ZenProxy Relay 并行示例
通过服务端 /api/relay 端点，并行使用 10 个不同代理访问 cn.bing.com
无需本地 sing-box 客户端，直接调用服务端转发
"""

import asyncio
import aiohttp

# === 配置 ===
ZENPROXY_SERVER = "https://zenproxy.top"
ZENPROXY_API_KEY = "xxx"
PROXY_COUNT = 10
TARGET_URL = "https://cn.bing.com"


async def relay_request(session: aiohttp.ClientSession, index: int) -> dict:
    """通过 relay 端点转发请求"""
    url = (
        f"{ZENPROXY_SERVER}/api/relay"
        f"?api_key={ZENPROXY_API_KEY}"
        f"&url={TARGET_URL}"
    )
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            ssl=False,
        ) as resp:
            body = await resp.read()
            proxy_ip = resp.headers.get("X-Proxy-IP", "?")
            proxy_country = resp.headers.get("X-Proxy-Country", "?")
            proxy_name = resp.headers.get("X-Proxy-Name", "?")
            return {
                "index": index,
                "status": resp.status,
                "size": len(body),
                "ip": proxy_ip,
                "country": proxy_country,
                "name": proxy_name,
                "success": resp.status == 200,
            }
    except Exception as e:
        return {
            "index": index,
            "error": str(e),
            "success": False,
        }


async def main():
    print(f"{'='*60}")
    print(f"  Relay 并行示例")
    print(f"  目标: {TARGET_URL}")
    print(f"  并行: {PROXY_COUNT} 个请求，每个走不同代理")
    print(f"{'='*60}\n")

    async with aiohttp.ClientSession() as session:
        tasks = [relay_request(session, i) for i in range(PROXY_COUNT)]
        results = await asyncio.gather(*tasks)

    success = 0
    for r in results:
        if r["success"]:
            success += 1
            print(f"  [✓] #{r['index']:>2}  {r['ip']:<15}  {r['country']}  HTTP {r['status']}  {r['size']} bytes")
        else:
            print(f"  [✗] #{r['index']:>2}  {r.get('error', 'unknown')}")

    print(f"\n结果: {success}/{len(results)} 成功")


if __name__ == "__main__":
    asyncio.run(main())
