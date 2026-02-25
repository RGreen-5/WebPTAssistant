from collections import Counter, defaultdict
from urllib.parse import urlsplit


def _url_key(u: str) -> str:
    p = urlsplit(u)
    return f"{p.scheme}://{p.netloc}{p.path}"

# Optional: enrich vague ZAP alert names with plain-English context
INTERPRETATION_MAP = {
    "Non-Storable Content": {
        "risk_explanation": (
            "The response includes cache-control headers that prevent browser caching. "
            "This is generally expected for dynamic or sensitive pages (e.g., login areas)."
        ),
        "security_impact": "Low to none. Often intentional.",
        "recommended_action": "No action required unless caching policy contradicts application design.",
    },
    "User Agent Fuzzer": {
        "risk_explanation": "ZAP attempted user-agent manipulation during testing; this is informational telemetry.",
        "security_impact": "Informational only.",
        "recommended_action": "No remediation required.",
    },
}

def classify_exploitability(alert_name: str, zap_risk: str) -> str:
    name = (alert_name or "").lower()
    risk = (zap_risk or "").strip().lower()

    if "header" in name or "policy" in name:
        return "Potentially Exploitable" if risk in ("high", "medium", "low") else "Informational"

    exploitable_keywords = [
        "sql injection", "sqli",
        "cross site scripting", "xss",
        "command injection",
        "remote code execution", "rce",
        "path traversal", "directory traversal",
        "file upload",
        "xxe", "ssrf",
        "authentication bypass",
        "insecure deserialization", "deserialization",
    ]

    if any(k in name for k in exploitable_keywords):
        return "Exploitable"

    if risk in ("high", "medium", "low"):
        return "Potentially Exploitable"

    return "Informational"

def normalize_zap_alerts(alerts: list[dict], baseurl: str) -> tuple[list[dict], dict]:
    groups = defaultdict(list)

    for a in alerts:
        name = a.get("alert", "Unknown")
        risk = a.get("risk", "Unknown")
        conf = a.get("confidence", "Unknown")
        groups[(name, risk, conf)].append(a)

    zap_risk_counts = Counter()
    exploitability_counts = Counter()
    grouped: list[dict] = []

    for (name, risk, conf), items in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
        zap_risk_counts[risk] += len(items)

        # Derive exploitability classification (based on alert name + ZAP risk)
        exploitability = classify_exploitability(name, risk)
        exploitability_counts[exploitability] += len(items)

        # Optional interpretation add-on if known
        interpretation = INTERPRETATION_MAP.get(name)

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
	    "exploitability": exploitability, 
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
        "zap_risk_instance_counts": dict(zap_risk_counts),
	"exploitability_instance_counts": dict(exploitability_counts),
        "top_groups": [
		{
		    "alert": g["alert"],
		    "risk": g["risk"],
    		    "instances": g["instances"]
		} for g in grouped[:15]
	],
    }
    return grouped, summary
