import time
from urllib.parse import urlparse

import requests
from zapv2 import ZAPv2


def wait_for_zap(zap_proxy: str, timeout_s: int = 60) -> None:
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout_s:
        try:
            r = requests.get(f"{zap_proxy}/JSON/core/view/version/", timeout=3)
            r.raise_for_status()
            return
        except Exception as e:
            last = e
            time.sleep(1)
    raise RuntimeError(f"ZAP not reachable at {zap_proxy} after {timeout_s}s: {last}")


def _fetch_alerts_paged(
    zap: ZAPv2,
    *,
    baseurl: str,
    page_size: int = 100,
    max_total: int = 3000,
    retries: int = 3,
) -> list[dict]:
    alerts: list[dict] = []
    start = 0

    while start < max_total:
        last_exc = None

        for _ in range(retries):
            try:
                batch = zap.core.alerts(baseurl=baseurl, start=start, count=page_size)
                if not batch:
                    return alerts

                alerts.extend(batch)

                if len(batch) < page_size:
                    return alerts

                start += page_size
                last_exc = None
                break

            except (
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
            ) as e:
                last_exc = e
                time.sleep(1)

        if last_exc is not None:
            return alerts

    return alerts


def zap_fast_scan(
    target: str,
    zap_proxy: str,
    exclude_prefixes: list[str],
    spider_budget_s: int,
    ascan_budget_s: int,
) -> dict:
    wait_for_zap(zap_proxy, timeout_s=60)

    zap = ZAPv2(apikey="", proxies={"http": zap_proxy, "https": zap_proxy})

    u = urlparse(target)
    base = f"{u.scheme}://{u.netloc}"

    # Exclusions
    for p in exclude_prefixes:
        try:
            zap.core.exclude_from_proxy(f"{base}{p}.*")
        except Exception:
            pass

    def _interesting_param(url: str) -> bool:
        s = (url or "").lower()
        keys = [
            "pass", "password", "pwd",
            "user", "username", "email",
            "id", "qid", "uid",
            "q", "query", "search",
            "redirect", "return", "next", "url",
            "page", "file", "path", "include",
        ]
        return any(k in s for k in keys)

    # Lighter spider tuning
    try:
        zap.spider.set_option_max_duration(spider_budget_s)
    except Exception:
        pass
    try:
        zap.spider.set_option_max_depth(5)
    except Exception:
        pass
    try:
        zap.spider.set_option_max_children(50)
    except Exception:
        pass

    # Seed root
    try:
        zap.urlopen(target)
        time.sleep(1)
    except Exception:
        pass

    # Spider
    spider_id = zap.spider.scan(target)
    t0 = time.time()
    while int(zap.spider.status(spider_id)) < 100:
        if time.time() - t0 > spider_budget_s:
            try:
                zap.spider.stop(spider_id)
            except Exception:
                pass
            break
        time.sleep(1)

    # Active scan settings
    try:
        zap.ascan.set_option_attack_strength("MEDIUM")
        zap.ascan.set_option_alert_threshold("MEDIUM")
    except Exception:
        pass

    # Discover parameterised URLs, but only seed a few
    try:
        discovered = zap.core.urls(base)
    except Exception:
        discovered = []

    param_urls = [x for x in discovered if "?" in (x or "")]
    param_urls.sort(key=lambda x: (not _interesting_param(x), len(x)))
    param_urls = param_urls[:10]

    for x in param_urls:
        try:
            zap.urlopen(x)
            time.sleep(0.05)
        except Exception:
            pass

    # ONE active scan only
    ascan_id = zap.ascan.scan(target)

    t1 = time.time()
    while int(zap.ascan.status(ascan_id)) < 100:
        if time.time() - t1 > ascan_budget_s:
            try:
                zap.ascan.stop(ascan_id)
            except Exception:
                pass
            break
        time.sleep(5)

    alerts = _fetch_alerts_paged(
        zap,
        baseurl=base,
        page_size=100,
        max_total=3000,
        retries=3,
    )

    return {
        "target": target,
        "zap_proxy": zap_proxy,
        "exclude_prefixes": exclude_prefixes,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "spider_budget_s": spider_budget_s,
        "ascan_budget_s": ascan_budget_s,
        "param_urls_considered": len(param_urls),
        "alerts_truncated": (len(alerts) >= 3000),
        "alerts": alerts,
        "alert_instances": len(alerts),
    }
