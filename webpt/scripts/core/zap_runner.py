import time
import requests
from urllib.parse import urlparse
from zapv2 import ZAPv2

def _fetch_alerts_paged(zap: ZAPv2, base: str, page_size: int = 200, max_total: int = 12000) -> list:

    """
    Robust alert collection:
    - small pages to avoid large HTTP responses
    - retries on broken chunks / transient connection errors
    - hard cap to prevent huge disk writes
    Returns partial results if ZAP connection breaks.
    """

    alerts = []
    start = 0

    while start < max_total:
        last_exc = None

        for _ in range(5):
            try:
                batch = zap.core.alerts(baseurl=base, start=start, count=page_size)
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
            # Return what we have rather than crashing the whole scan
            return alerts

    return alerts


def zap_fast_scan(
    target: str,
    zap_proxy: str,
    exclude_prefixes: list[str],
    spider_budget_s: int,
    ascan_budget_s: int,
) -> dict:
    # Preflight: fail fast if ZAP not reachable
    r = requests.get(f"{zap_proxy}/JSON/core/view/version/", timeout=3)
    r.raise_for_status()

    zap = ZAPv2(apikey="", proxies={"http": zap_proxy, "https": zap_proxy})

    u = urlparse(target)
    base = f"{u.scheme}://{u.netloc}"

    # Exclusions (scope control)
    for p in exclude_prefixes:
        zap.core.exclude_from_proxy(f"{base}{p}.*")

    def _interesting_param(url: str) -> bool:
        s = (url or "").lower()
        keys = [
            "pass", "password", "pwd",
            "user", "username", "email",
            "id", "qid", "uid",
            "q", "query", "search",
            "token", "csrf", "auth",
            "redirect", "return", "next", "url",
        ]
        return any(k in s for k in keys)

    # Best effort spider tuning
    try:
        zap.spider.set_option_max_duration(spider_budget_s)
    except Exception:
        pass
    try:
        zap.spider.set_option_max_depth(10)
    except Exception:
        pass
    try:
        zap.spider.set_option_max_children(200)
    except Exception:
        pass

    # Seed the target
    try:
        zap.urlopen(target)
        time.sleep(1)
    except Exception:
        pass

    # Spider with wall clock budget
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

    # Increase scan aggressiveness
    try:
        zap.ascan.set_option_attack_strength("HIGH")
        zap.ascan.set_option_alert_threshold("LOW")
    except Exception:
        pass

    # Parameterised URL boost
    try:
        discovered = zap.core.urls(base)
    except Exception:
        discovered = []

    param_urls = [x for x in discovered if "?" in (x or "")]
    param_urls.sort(key=lambda x: (not _interesting_param(x), len(x)))

    MAX_PARAM_URLS = 30
    param_urls = param_urls[:MAX_PARAM_URLS]

    for x in param_urls:
        try:
            zap.urlopen(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Active scan main target
    ascan_id = zap.ascan.scan(target)

    # Actively scan parameterised URLs too
    for x in param_urls:
        try:
            zap.ascan.scan(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Wait for main scan completion (budgeted)
    t1 = time.time()
    while int(zap.ascan.status(ascan_id)) < 100:
        if time.time() - t1 > ascan_budget_s:
            try:
                zap.ascan.stop(ascan_id)
            except Exception:
                pass
            break
        time.sleep(5)

    # Pull alerts robustly (small pages + retries + cap)
    alerts = _fetch_alerts_paged(zap, base=base, page_size=200, max_total=12000)

    return {
        "target": target,
        "zap_proxy": zap_proxy,
        "exclude_prefixes": exclude_prefixes,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "spider_budget_s": spider_budget_s,
        "ascan_budget_s": ascan_budget_s,
        "param_urls_considered": len(param_urls),
        "alerts_truncated": (len(alerts) >= 12000),
        "alerts": alerts,
        "alert_instances": len(alerts),
    }
