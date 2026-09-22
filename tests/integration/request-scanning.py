from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


def memory_request(
    router_url: str, token: str, operation: str, *, heavy: bool = True
) -> dict[str, object] | None:
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
    if not heavy:
        body = {"items": [{"content": "CI scanner recovery"}], "async": True}
    if operation == "recall":
        body = {"query": "CI metadata scan" if heavy else "CI scanner recovery"}
    suffix = "/recall" if operation == "recall" else ""
    request = Request(  # noqa: S310 - URL is the isolated CI router.
        f"{router_url}/v1/default/banks/main/memories{suffix}",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=20) as response:
            result = json.load(response)
        assert isinstance(result, dict), result
        return result
    except HTTPError as error:
        if not heavy:
            raise
        kind = "recall" if operation == "recall" else "request"
        with error:
            assert error.code == 503, error.code
            assert error.headers.get("Retry-After") == "1", error.headers
            result = json.load(error)
        assert result == {
            "error": f"{kind}_scan_unavailable",
            "message": f"{kind} safety scan timed out",
        }, result
        return None


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
    assert len(delays) >= 3, delays
    assert max(delays) < 1.0, delays
    if result is None:
        recovered = memory_request(router_url, token, operation, heavy=False)
        assert recovered is not None
        if operation == "recall":
            assert recovered.get("results") and not recovered.get("partial"), recovered
        else:
            assert recovered.get("success") is True or recovered.get("ok") is True, recovered
    elif operation == "recall":
        assert result.get("results") == [] and not result.get("partial"), result
    else:
        assert result.get("queued") is True, result


if __name__ == "__main__":
    main()
