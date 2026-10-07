from __future__ import annotations

import random
import threading
import time
from typing import Any

import requests

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


class ProxyRotator:
    def __init__(self, test_url: str = "http://httpbin.org/ip", test_timeout: int = 5) -> None:
        self._proxies: list[str] = []
        self._lock = threading.Lock()
        self._index = 0
        self._last_fetch = 0.0
        self._test_url = test_url
        self._test_timeout = test_timeout
        self._working: list[str] = []

    def fetch_proxies(self, min_ttl: int = 300) -> int:
        now = time.time()
        if now - self._last_fetch < min_ttl and self._proxies:
            return len(self._proxies)
        all_proxies: set[str] = set()
        for url in PROXY_SOURCES:
            try:
                r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10)
                if r.status_code == 200:
                    for line in r.text.strip().splitlines():
                        line = line.strip()
                        if line and ":" in line:
                            all_proxies.add(f"http://{line}")
            except Exception:
                continue
        with self._lock:
            self._proxies = list(all_proxies)
            random.shuffle(self._proxies)
            self._last_fetch = now
            self._index = 0
        return len(self._proxies)

    def verify_proxies(self, max_workers: int = 50) -> list[str]:
        import concurrent.futures

        def _test(proxy: str) -> str | None:
            try:
                r = requests.get(
                    self._test_url,
                    proxies={"http": proxy, "https": proxy},
                    timeout=self._test_timeout,
                    headers={"User-Agent": USER_AGENT},
                )
                if r.status_code == 200:
                    return proxy
            except Exception:
                pass
            return None

        with self._lock:
            to_test = self._proxies[:]
        working: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_test, p): p for p in to_test}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    working.append(result)
        with self._lock:
            self._working = working
        return working

    def get_proxy(self) -> dict[str, str] | None:
        with self._lock:
            if not self._working:
                if not self._proxies:
                    return None
                proxy = self._proxies[self._index % len(self._proxies)]
                self._index += 1
            else:
                proxy = self._working[self._index % len(self._working)]
                self._index += 1
        return {"http": proxy, "https": proxy}

    def request(self, url: str, method: str = "GET", **kwargs: Any) -> requests.Response | None:
        proxy = self.get_proxy()
        if proxy:
            kwargs.setdefault("timeout", 10)
            kwargs.setdefault("headers", {}).setdefault("User-Agent", USER_AGENT)
            try:
                return requests.request(method, url, proxies=proxy, **kwargs)
            except Exception:
                pass
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("headers", {}).setdefault("User-Agent", USER_AGENT)
        try:
            return requests.request(method, url, **kwargs)
        except Exception:
            return None


_global_rotator: ProxyRotator | None = None


def get_rotator() -> ProxyRotator:
    global _global_rotator
    if _global_rotator is None:
        _global_rotator = ProxyRotator()
    return _global_rotator


def rotate_request(url: str, method: str = "GET", **kwargs: Any) -> requests.Response | None:
    return get_rotator().request(url, method, **kwargs)
