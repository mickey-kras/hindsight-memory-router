from __future__ import annotations

import json
import sys
import time
import urllib.request


def contains_marker(response: object, marker: str) -> bool:
    if not isinstance(response, dict) or not isinstance(response.get("results"), list):
        raise ValueError("recall response must contain a results list")
    if response.get("partial") or response.get("failed_banks"):
        raise ValueError("recall failed for at least one bank")
    return any(
        isinstance(result, dict)
        and isinstance(result.get("text"), str)
        and marker in result["text"]
        for result in response["results"]
    )


def wait_for_marker(base_url: str, token: str, marker: str, timeout: float = 120) -> dict:
    request = urllib.request.Request(  # noqa: S310 - local integration router URL
        f"{base_url}/v1/default/banks/main/memories/recall",
        data=json.dumps({"query": marker}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        with opener.open(request, timeout=min(5, remaining)) as response:  # noqa: S310 - caller supplies the local integration router URL
            payload = json.load(response)
        if contains_marker(payload, marker):
            return payload
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise TimeoutError("seeded marker did not become recallable before the smoke deadline")


if __name__ == "__main__":
    print(json.dumps(wait_for_marker(*sys.argv[1:4])))
