import json, os, subprocess, time
from urllib.parse import urlparse
from zapv2 import ZAPv2

OUTPUT_DIR = "output"
ZAP_PROXY = "http://127.0.0.1:8080"

SPIDER_MAX_SECONDS = 120
ASCAN_MAX_SECONDS = 600  # 10 minutes
EXCLUDE_PREFIXES = ["/twiki/", "/phpMyAdmin/"]

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {"cmd": " ".join(cmd), "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    target = input("Target URL (e.g. http://192.168.56.101/): ").strip()
    u = urlparse(target)
    if not u.scheme or not u.netloc:
        raise SystemExit("Invalid URL. Example: http://192.168.56.101/")
    host = u.hostname

    print("[1/2] Nmap top 200 ports")
    with open(os.path.join(OUTPUT_DIR, "nmap_raw.json"), "w", encoding="utf-8") as f:
        json.dump(run(["nmap", "-sT", "-sV", "--top-ports", "200", "-Pn", host]), f, indent=2)

    zap = ZAPv2(apikey="", proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    base = f"{u.scheme}://{u.netloc}"

    for p in EXCLUDE_PREFIXES:
        zap.core.exclude_from_proxy(f"{base}{p}.*")

    print("[2/2] ZAP fast scan (budgeted)")
    zap.urlopen(target)
    time.sleep(2)

    spider_id = zap.spider.scan(target)
    t0 = time.time()
    while int(zap.spider.status(spider_id)) < 100:
        if time.time() - t0 > SPIDER_MAX_SECONDS:
            zap.spider.stop(spider_id)
            break
        time.sleep(1)

    ascan_id = zap.ascan.scan(target)
    t1 = time.time()
    while int(zap.ascan.status(ascan_id)) < 100:
        if time.time() - t1 > ASCAN_MAX_SECONDS:
            zap.ascan.stop(ascan_id)
            break
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=target)
    out = {
        "target": target,
        "excluded": EXCLUDE_PREFIXES,
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "spider_budget_s": SPIDER_MAX_SECONDS,
        "ascan_budget_s": ASCAN_MAX_SECONDS,
        "alert_count": len(alerts),
        "alerts": alerts,
    }

    with open(os.path.join(OUTPUT_DIR, "zap_alerts.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("Done")
    print("alert_count =", out["alert_count"])
    print("Saved output/nmap_raw.json and output/zap_alerts.json")

if __name__ == "__main__":
    main()
