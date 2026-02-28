import time
import requests
from urllib.parse import urlparse
from zapv2 import ZAPv2


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

    # Exclusions (scope control) - treat entries as path prefixes (your current CLI behavior)
    for p in exclude_prefixes:
        zap.core.exclude_from_proxy(f"{base}{p}.*")

    def _interesting_param(url: str) -> bool:
        s = (url or "").lower()
        # Generic “high value” parameter hints (NOT app-specific)
        keys = [
            "pass", "password", "pwd",
            "user", "username", "email",
            "id", "qid", "uid",
            "q", "query", "search",
            "token", "csrf", "auth",
            "redirect", "return", "next", "url"
        ]
        return any(k in s for k in keys)

    # Best-effort spider tuning (options may not exist in some ZAP builds)
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
        # If seed fails, still attempt spider (sometimes works anyway)
        pass

    # Spider with wall-clock budget
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

    # Increase scan aggressiveness for SQLi detection
    try:
        zap.ascan.set_option_attack_strength("HIGH")
        zap.ascan.set_option_alert_threshold("LOW")
    except Exception:
        pass

    # Generic parameterised URL boost: actively scan parameterised endpoints ZAP discovered
    try:
        discovered = zap.core.urls(base)
    except Exception:
        discovered = []

    param_urls = [x for x in discovered if "?" in (x or "")]
    # Prioritise URLs with “interesting” parameter names, then shorter URLs first
    param_urls.sort(key=lambda x: (not _interesting_param(x), len(x)))

    # Limit to keep runtime sane
    MAX_PARAM_URLS = 30
    param_urls = param_urls[:MAX_PARAM_URLS]

    # Seed param URLs into history
    for x in param_urls:
        try:
            zap.urlopen(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Start main active scan
    ascan_id = zap.ascan.scan(target)

    # ALSO actively scan the parameterised URLs explicitly (this is the key improvement)
    for x in param_urls:
        try:
            zap.ascan.scan(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Wait for main active scan to complete (budgeted)
    t1 = time.time()
    while int(zap.ascan.status(ascan_id)) < 100:
        if time.time() - t1 > ascan_budget_s:
            try:
                zap.ascan.stop(ascan_id)
            except Exception:
                pass
            break
        time.sleep(5)

    # Pull alerts for the whole site (base), not only the specific target URL
    alerts = []
    start = 0
    page_size = 500  # tune: 200–1000; smaller = safer
    while True:
        batch = zap.core.alerts(baseurl=base, start=start, count=page_size)
        if not batch:
            break
        alerts.extend(batch)
        if len(batch) < page_size:
            break
        start += page_size

    return {
        "target": target,
        "zap_proxy": zap_proxy,
        "exclude_prefixes": exclude_prefixes,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "spider_budget_s": spider_budget_s,
        "ascan_budget_s": ascan_budget_s,
        "param_urls_considered": len(param_urls),
        "alerts": alerts,
        "alert_instances": len(alerts),
    }
