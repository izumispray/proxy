"""
ZenProxy Relay 轮换示例
通过服务端 /api/relay 端点，每批 10 个并行，共 100 次请求
每次请求服务端随机分配不同代理，无需本地客户端
"""

import asyncio
import aiohttp
import time

# === 配置 ===
ZENPROXY_SERVER = "https://zenproxy.top"
ZENPROXY_API_KEY = "xxx"

BATCH_SIZE = 10
TOTAL_REQUESTS = 100
TARGET_URL = "https://cn.bing.com"


async def relay_request(session: aiohttp.ClientSession, request_id: int) -> dict:
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
            return {
                "id": request_id,
                "status": resp.status,
                "size": len(body),
                "ip": resp.headers.get("X-Proxy-IP", "?"),
                "country": resp.headers.get("X-Proxy-Country", "?"),
                "success": resp.status == 200,
            }
    except Exception as e:
        return {
            "id": request_id,
            "error": str(e),
            "success": False,
        }


async def main():
    total_batches = TOTAL_REQUESTS // BATCH_SIZE

    print(f"{'='*60}")
    print(f"  Relay 轮换示例")
    print(f"  目标: {TARGET_URL}")
    print(f"  总请求: {TOTAL_REQUESTS}, 每批并行: {BATCH_SIZE}, 共 {total_batches} 批")
    print(f"{'='*60}\n")

    all_results = []
    seen_ips = set()
    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        for batch_idx in range(total_batches):
            batch_start = batch_idx * BATCH_SIZE

            tasks = [
                relay_request(session, batch_start + i)
                for i in range(BATCH_SIZE)
            ]
            results = await asyncio.gather(*tasks)
            all_results.extend(results)

            success = sum(1 for r in results if r["success"])
            failed = BATCH_SIZE - success
            batch_ips = {r["ip"] for r in results if r["success"]}
            seen_ips.update(batch_ips)

            print(
                f"  批次 {batch_idx+1:>2}/{total_batches}: "
                f"{success} 成功, {failed} 失败  "
                f"(请求 #{batch_start+1}-#{batch_start+BATCH_SIZE})  "
                f"IP: {', '.join(batch_ips) if batch_ips else '-'}"
            )

    elapsed = time.time() - start_time
    total_success = sum(1 for r in all_results if r["success"])
    total_failed = len(all_results) - total_success

    print(f"\n{'='*60}")
    print(f"  完成! 耗时 {elapsed:.1f}s")
    print(f"  总计: {total_success} 成功, {total_failed} 失败 / {len(all_results)} 请求")
    print(f"  去重 IP 数: {len(seen_ips)}")
    print(f"  平均: {elapsed/len(all_results)*1000:.0f}ms/请求")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
