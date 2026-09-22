from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import ProxyHandler, Request, build_opener


def memory_request(router_url: str, token: str, operation: str) -> dict[str, object]:
    body = {
        "items": [
            {
                "content": "project status is green",
                "metadata": {
                    f"key{i}": f"meeting notes archive item {i} ordinary reference information"
                    for i in range(1200)
                },
            }
        ]
    }
    if operation == "recall":
        body = {"query": "CI metadata scan"}
    suffix = "/recall" if operation == "recall" else ""
    request = Request(  # noqa: S310 - URL is the isolated CI router.
        f"{router_url}/v1/default/banks/main/memories{suffix}",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with build_opener(ProxyHandler({})).open(request, timeout=20) as response:
        return json.load(response)


def main() -> None:
    router_url, token, operation = sys.argv[1:]
    delays = []
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(memory_request, router_url, token, operation)
        while not pending.done():
            time.sleep(0.05)
            started = time.monotonic()
            with build_opener(ProxyHandler({})).open(
                f"{router_url}/health/live", timeout=2
            ) as response:
                assert json.load(response) == {"status": "alive"}
            delays.append(time.monotonic() - started)
        result = pending.result()
    if operation == "recall":
        assert result.get("results") == [] and not result.get("partial"), result
    else:
        assert result.get("queued") is True, result
    assert len(delays) >= 3, delays
    assert max(delays) < 1.0, delays


if __name__ == "__main__":
    main()
