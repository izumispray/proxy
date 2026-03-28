"""
ZenProxy 本地客户端 - 轮换代理示例
固定 10 个绑定端口，每批 10 个并行请求，用完换一批新代理，共访问 100 次 cn.bing.com

流程：
  1. 从服务器 fetch 100 个代理存入 store
  2. 取前 10 个 → 创建绑定 → 并行请求 → 删除绑定
  3. 取下 10 个 → 创建绑定 → 并行请求 → 删除绑定
  4. 重复直到 100 次请求完成（共 10 批）
"""

import asyncio
import aiohttp
import time

# === 配置 ===
CLASH_API = "http://127.0.0.1:9090"
CLASH_SECRET = "your-secret"  # sing-box config.json 中的 secret
ZENPROXY_SERVER = "https://zenproxy.top"
ZENPROXY_API_KEY = "xxx"

BATCH_SIZE = 10      # 每批并行数
TOTAL_REQUESTS = 100  # 总请求数
TARGET_URL = "https://cn.bing.com"


def headers():
    return {"Authorization": f"Bearer {CLASH_SECRET}", "Content-Type": "application/json"}


async def fetch_proxies(session: aiohttp.ClientSession, count: int) -> list[dict]:
    """从服务器 fetch 代理存入 store，返回代理列表"""
    print(f"[准备] 从 {ZENPROXY_SERVER} 获取 {count} 个代理...")
    async with session.post(
        f"{CLASH_API}/fetch",
        headers=headers(),
        json={
            "server": ZENPROXY_SERVER,
            "api_key": ZENPROXY_API_KEY,
            "count": count,
        },
    ) as resp:
        result = await resp.json()
        if resp.status != 200:
            raise Exception(f"Fetch 失败: {result}")
        print(f"       已获取 {result['added']} 个代理\n")

    # 获取 store 中的代理列表
    async with session.get(f"{CLASH_API}/store", headers=headers()) as resp:
        result = await resp.json()
        return result["proxies"]


async def create_bindings(session: aiohttp.ClientSession, proxy_ids: list[str]) -> list[dict]:
    """为指定代理创建绑定，返回绑定信息"""
    async with session.post(
        f"{CLASH_API}/bindings/batch",
        headers=headers(),
        json={"proxy_ids": proxy_ids},
    ) as resp:
        result = await resp.json()
        return result.get("bindings", [])


async def delete_bindings(session: aiohttp.ClientSession, tags: list[str]):
    """逐个删除绑定"""
    for tag in tags:
        async with session.delete(
            f"{CLASH_API}/bindings/{tag}", headers=headers()
        ) as resp:
            pass  # 忽略错误，静默删除


async def request_via_proxy(proxy_url: str, request_id: int) -> dict:
    """通过本地代理端口访问目标"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                TARGET_URL,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                body = await resp.read()
                return {
                    "id": request_id,
                    "proxy": proxy_url,
                    "status": resp.status,
                    "size": len(body),
                    "success": True,
                }
    except Exception as e:
        return {
            "id": request_id,
            "proxy": proxy_url,
            "error": str(e),
            "success": False,
        }


async def run_batch(
    session: aiohttp.ClientSession,
    proxies: list[dict],
    batch_index: int,
    start_request_id: int,
) -> list[dict]:
    """执行一批：创建绑定 → 并行请求 → 删除绑定"""
    batch_num = batch_index + 1
    proxy_ids = [p["id"] for p in proxies]

    # 创建绑定
    bindings = await create_bindings(session, proxy_ids)
    if not bindings:
        print(f"  批次 {batch_num}: 绑定创建失败，跳过")
        return []

    port_map = {b["proxy_id"]: b["local_port"] for b in bindings}
    bound_tags = proxy_ids  # tag 就是 proxy_id

    # 并行请求
    tasks = []
    for i, proxy in enumerate(proxies):
        port = port_map.get(proxy["id"])
        if port:
            proxy_url = f"http://127.0.0.1:{port}"
            tasks.append(request_via_proxy(proxy_url, start_request_id + i))

    results = await asyncio.gather(*tasks)

    # 删除绑定，释放端口给下一批
    await delete_bindings(session, bound_tags)

    # 打印本批结果
    success = sum(1 for r in results if r["success"])
    failed = len(results) - success
    print(f"  批次 {batch_num:>2}/{ TOTAL_REQUESTS // BATCH_SIZE}: "
          f"{success} 成功, {failed} 失败  "
          f"(请求 #{start_request_id+1}-#{start_request_id+len(results)})")

    return results


async def cleanup(session: aiohttp.ClientSession):
    """清理所有绑定和代理"""
    async with session.delete(f"{CLASH_API}/bindings/all", headers=headers()) as resp:
        pass
    async with session.delete(f"{CLASH_API}/store", headers=headers()) as resp:
        pass


async def main():
    total_batches = TOTAL_REQUESTS // BATCH_SIZE

    print(f"{'='*60}")
    print(f"  轮换代理示例")
    print(f"  目标: {TARGET_URL}")
    print(f"  总请求: {TOTAL_REQUESTS}, 每批并行: {BATCH_SIZE}, 共 {total_batches} 批")
    print(f"  每批使用不同的代理 IP")
    print(f"{'='*60}\n")

    async with aiohttp.ClientSession() as session:
        # 清理旧数据
        await cleanup(session)

        # 一次性 fetch 足够的代理
        proxies = await fetch_proxies(session, TOTAL_REQUESTS)

        if len(proxies) < TOTAL_REQUESTS:
            print(f"  警告: 只获取到 {len(proxies)} 个代理，不足 {TOTAL_REQUESTS}")

        # 分批执行
        all_results = []
        start_time = time.time()

        for batch_idx in range(total_batches):
            batch_start = batch_idx * BATCH_SIZE
            batch_proxies = proxies[batch_start : batch_start + BATCH_SIZE]

            if not batch_proxies:
                print(f"  批次 {batch_idx+1}: 没有剩余代理，停止")
                break

            results = await run_batch(session, batch_proxies, batch_idx, batch_start)
            all_results.extend(results)

        elapsed = time.time() - start_time

        # 最终汇总
        total_success = sum(1 for r in all_results if r["success"])
        total_failed = len(all_results) - total_success

        print(f"\n{'='*60}")
        print(f"  完成! 耗时 {elapsed:.1f}s")
        print(f"  总计: {total_success} 成功, {total_failed} 失败 / {len(all_results)} 请求")
        print(f"  平均: {elapsed/len(all_results)*1000:.0f}ms/请求 (含绑定开销)")
        print(f"  使用了 {len(all_results)} 个不同 IP")
        print(f"{'='*60}")

        # 清理
        await cleanup(session)
        print("\n已清理所有代理和绑定")


if __name__ == "__main__":
    asyncio.run(main())
