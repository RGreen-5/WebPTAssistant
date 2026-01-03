import gzip
import json
import os
from collections import Counter, defaultdict
from urllib.parse import urlsplit

INFILE = "output/zap_alerts.json.gz"
OUT_SUMMARY = "output/zap_summary.json"
OUT_TOP = "output/zap_top_alerts.json"

# How many example instances to keep per alert group
MAX_EXAMPLES_PER_GROUP = 5


def load_json(path: str):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def url_key(u: str) -> str:
    # Remove query string to reduce duplicates
    try:
        parts = urlsplit(u)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"
    except Exception:
        return u


def main():
    if not os.path.exists(INFILE):
        raise SystemExit(f"Missing {INFILE}. Run: gzip -9 output/zap_alerts.json")

    raw = load_json(INFILE)
    alerts = raw.get("alerts", raw.get("alerts", []))

    # Group by (alert, risk, confidence)
    groups = defaultdict(list)
    for a in alerts:
        name = a.get("alert", "Unknown")
        risk = a.get("risk", "Unknown")
        conf = a.get("confidence", "Unknown")
        key = (name, risk, conf)
        groups[key].append(a)

    # Build summary
    severity_counts = Counter()
    for (_, risk, _), items in groups.items():
        severity_counts[risk] += len(items)

    # Create grouped output with limited examples
    grouped = []
    for (name, risk, conf), items in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
        examples = []
        seen = set()
        for it in items:
            u = it.get("url", "")
            p = it.get("param", "")
            method = it.get("method", "")
            k = (url_key(u), p, method)
            if k in seen:
                continue
            seen.add(k)
            examples.append({"url": u, "url_key": url_key(u), "param": p, "method": method})
            if len(examples) >= MAX_EXAMPLES_PER_GROUP:
                break

        grouped.append({
            "alert": name,
            "risk": risk,
            "confidence": conf,
            "instances": len(items),
            "example_instances": examples,
            "cweid": items[0].get("cweid"),
            "wascid": items[0].get("wascid"),
            "description": items[0].get("description"),
            "solution": items[0].get("solution"),
            "reference": items[0].get("reference"),
        })

    summary = {
        "target": raw.get("target"),
        "raw_alert_instances": len(alerts),
        "unique_alert_groups": len(grouped),
        "risk_instance_counts": dict(severity_counts),
        "top_groups_by_instances": [
            {"alert": g["alert"], "risk": g["risk"], "confidence": g["confidence"], "instances": g["instances"]}
            for g in grouped[:20]
        ],
        "notes": [
            "ZAP produces repeated alert instances per URL/parameter; grouped output is what you present.",
            "Counts are instances, not unique vulnerabilities. Use groups for reporting."
        ]
    }

    with open(OUT_SUMMARY, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(OUT_TOP, "w", encoding="utf-8") as f:
        json.dump(grouped[:200], f, indent=2)

    print("Wrote:", OUT_SUMMARY)
    print("Wrote:", OUT_TOP)


if __name__ == "__main__":
    main()
