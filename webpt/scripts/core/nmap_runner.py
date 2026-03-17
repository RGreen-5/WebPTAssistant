import subprocess
from urllib.parse import urlparse


def run_nmap_all_ports(target_url: str, timeout_s: int = 1800) -> dict:
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not extract host from target URL: {target_url}")

    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port

    # Scan the explicit web port first, then do service/version detection on it
    cmd = ["nmap", "-sT", "-sV", "-p", str(port), "--reason", "-Pn", host]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return {
        "command": " ".join(cmd),
        "returncode": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
        "host": host,
        "port": port,
    }


def run_nmap_http_sqli_check(target_url: str, timeout_s: int = 600) -> dict:
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not extract host from target URL: {target_url}")

    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port

    script_args = [
        f"http-sql-injection.url={parsed.path or '/'}"
    ]

    cmd = [
        "nmap",
        "-sT",
        "-Pn",
        "-p", str(port),
        "--script", "http-sql-injection",
        "--script-args", ",".join(script_args),
        host,
    ]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return {
        "command": " ".join(cmd),
        "returncode": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
        "host": host,
        "port": port,
        "target_url": target_url,
    }


def nmap_sqli_result_to_alerts(nmap_sqli_raw: dict) -> list[dict]:
    import re

    stdout = nmap_sqli_raw.get("stdout", "") or ""
    target_url = nmap_sqli_raw.get("target_url", "")

    alerts = []

    patterns = [
        r"SQL injection vulnerability",
        r"possible SQL injection",
        r"found the following SQL injection points",
        r"the following injections were found",
        r"might be vulnerable to SQL injection",
    ]

    if any(re.search(p, stdout, re.IGNORECASE) for p in patterns):
        alerts.append(
            {
                "alert": "SQL Injection (Nmap NSE)",
                "name": "SQL Injection (Nmap NSE)",
                "risk": "High",
                "confidence": "Medium",
                "url": target_url,
                "param": "",
                "method": "GET/POST",
                "pluginId": "NMAP-HTTP-SQLI",
                "cweid": "89",
                "wascid": "19",
                "description": "Nmap http-sql-injection script reported a likely SQL injection issue.",
                "solution": "Use parameterised queries / prepared statements and validate input.",
                "evidence": stdout[-2000:],
                "other": "",
                "tags": {
                    "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
                    "OWASP_2021_A03": "https://owasp.org/Top10/A03_2021-Injection/",
                },
            }
        )

    return alerts
