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

    # Exclusions (scope control)
    for p in exclude_prefixes:
        zap.core.exclude_from_proxy(f"{base}{p}.*")

    # Try to reduce spider explosion (best-effort, depends on ZAP build)
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

    # Seed
    zap.urlopen(target)
    time.sleep(1)

    # Spider with hard wall clock budget
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

    # Active scan with hard wall clock budget
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

    alerts = zap.core.alerts(baseurl=target)

    return {
        "target": target,
        "zap_proxy": zap_proxy,
        "exclude_prefixes": exclude_prefixes,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "spider_budget_s": spider_budget_s,
        "ascan_budget_s": ascan_budget_s,
        "alerts": alerts,
        "alert_instances": len(alerts),
    }
