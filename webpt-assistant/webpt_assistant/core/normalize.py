from collections import Counter, defaultdict
from urllib.parse import urlsplit


def _url_key(u: str) -> str:
    p = urlsplit(u)
    return f"{p.scheme}://{p.netloc}{p.path}"


def normalize_zap_alerts(alerts: list[dict], baseurl: str) -> tuple[list[dict], dict]:
    groups = defaultdict(list)

    for a in alerts:
        name = a.get("alert", "Unknown")
        risk = a.get("risk", "Unknown")
        conf = a.get("confidence", "Unknown")
        groups[(name, risk, conf)].append(a)

    risk_counts = Counter()
    grouped = []

    for (name, risk, conf), items in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
        risk_counts[risk] += len(items)

        examples = []
        seen = set()
        for it in items:
            u = it.get("url", "")
            method = it.get("method", "")
            param = it.get("param", "")
            key = (_url_key(u), method, param)
            if key in seen:
                continue
            seen.add(key)
            examples.append({"url": u, "url_key": _url_key(u), "method": method, "param": param})
            if len(examples) >= 5:
                break

        first = items[0]
        grouped.append({
            "alert": name,
            "risk": risk,
            "confidence": conf,
            "instances": len(items),
            "cweid": first.get("cweid"),
            "wascid": first.get("wascid"),
            "description": first.get("description"),
            "solution": first.get("solution"),
            "reference": first.get("reference"),
            "examples": examples,
        })

    summary = {
        "baseurl": baseurl,
        "raw_instances": len(alerts),
        "unique_groups": len(grouped),
        "risk_instance_counts": dict(risk_counts),
        "top_groups": [{"alert": g["alert"], "risk": g["risk"], "instances": g["instances"]} for g in grouped[:15]],
    }
    return grouped, summary
