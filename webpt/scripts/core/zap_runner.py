import time
import requests
from urllib.parse import urlparse
from zapv2 import ZAPv2


def wait_for_zap(zap_proxy: str, timeout_s: int = 45) -> None:
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


def zap_fast_scan(
    target: str,
    zap_proxy: str,
    exclude_prefixes: list[str],
    spider_budget_s: int,
    ascan_budget_s: int,
) -> dict:

    # Wait for ZAP to be ready
    wait_for_zap(zap_proxy, timeout_s=45)

    zap = ZAPv2(apikey="", proxies={"http": zap_proxy, "https": zap_proxy})

    u = urlparse(target)
    base = f"{u.scheme}://{u.netloc}"

    # Exclusions
    for p in exclude_prefixes:
        zap.core.exclude_from_proxy(f"{base}{p}.*")

    def _interesting_param(url: str) -> bool:
        s = (url or "").lower()
        keys = [
            "pass","password","pwd",
            "user","username","email",
            "id","qid","uid",
            "q","query","search",
            "token","csrf","auth",
            "redirect","return","next","url"
        ]
        return any(k in s for k in keys)

    # Spider config
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

    # Seed target
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

    # Active scan config
    try:
        zap.ascan.set_option_attack_strength("HIGH")
        zap.ascan.set_option_alert_threshold("LOW")
    except Exception:
        pass

    # Discover parameter URLs
    try:
        discovered = zap.core.urls(base)
    except Exception:
        discovered = []

    param_urls = [x for x in discovered if "?" in (x or "")]
    param_urls.sort(key=lambda x: (not _interesting_param(x), len(x)))

    param_urls = param_urls[:30]

    for x in param_urls:
        try:
            zap.urlopen(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Active scan
    ascan_id = zap.ascan.scan(target)

    for x in param_urls:
        try:
            zap.ascan.scan(x)
            time.sleep(0.2)
        except Exception:
            pass

    # Wait for scan completion
    t1 = time.time()
    while int(zap.ascan.status(ascan_id)) < 100:
        if time.time() - t1 > ascan_budget_s:
            try:
                zap.ascan.stop(ascan_id)
            except Exception:
                pass
            break
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=base)

    return {
        "target": target,
        "zap_proxy": zap_proxy,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "alerts": alerts,
        "alert_instances": len(alerts),
    }
