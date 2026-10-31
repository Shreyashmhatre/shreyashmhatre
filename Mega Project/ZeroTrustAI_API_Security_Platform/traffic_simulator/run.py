"""Bounded traffic scenarios, restricted to the local gateway only."""

import argparse
import asyncio
from collections import Counter
from urllib.parse import urlparse

import httpx

from common.config import Settings


async def run(scenario: str, base: str):
    url = urlparse(base)
    if url.hostname not in {"127.0.0.1", "localhost", "::1"} or url.scheme != "http":
        raise ValueError("Simulator only supports a local HTTP gateway")
    cfg = Settings()
    async with httpx.AsyncClient(base_url=base, timeout=15, trust_env=False) as client:
        login = await client.post(
            "/proxy/auth/login",
            json={
                "username": "alice",
                "password": cfg.demo_password.get_secret_value(),
            },
        )
        login.raise_for_status()
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
        calls = {
            "normal": [("/proxy/products", 200), ("/proxy/orders", 200), ("/proxy/orders/1", 200)],
            "bola": [("/proxy/orders/1", 200), ("/proxy/orders/2", 403)],
            "role": [("/proxy/admin/users", 403)],
            "burst": [("/proxy/products", None)] * (cfg.requests_per_minute + 8),
            "invalid-token": [("/proxy/orders", 401)],
        }[scenario]
        counts = Counter()
        for path, expected in calls:
            headers = {"Authorization": "Bearer invalid"} if scenario == "invalid-token" else auth
            response = await client.get(path, headers=headers)
            counts[response.status_code] += 1
            print(
                f"GET {path:25} {response.status_code}  "
                f"request={response.headers.get('x-request-id', '—')}"
            )
            if expected and response.status_code != expected:
                raise RuntimeError(
                    f"Expected {expected}, got {response.status_code}. "
                    "Clear previous rate windows by waiting 60 seconds."
                )
            if scenario != "burst":
                await asyncio.sleep(0.3)
        print("Observed status counts:", dict(counts))
        if scenario == "burst" and not counts[429]:
            raise RuntimeError("Expected a rate-limited response")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["normal", "bola", "role", "burst", "invalid-token"])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    asyncio.run(run(args.scenario, args.base_url))
