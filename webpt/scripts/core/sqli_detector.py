import hashlib
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests


SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"warning.*mysql",
    r"mysqli?",
    r"ora-\d+",
    r"odbc sql",
    r"syntax error",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite error",
    r"postgresql.*error",
    r"supplied argument is not a valid mysql",
    r"error in your sql syntax",
]

STRONG_PARAM_KEYS = {
    "id", "uid", "qid", "pid",
    "user", "username",
    "password", "pass", "pwd",
    "email",
    "q", "query", "search",
}


def _body_signature(text: str) -> tuple[int, str]:
    norm = " ".join((text or "").split())
    h = hashlib.sha256(norm[:200000].encode("utf-8", errors="ignore")).hexdigest()
    return len(norm), h


def _replace_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = []

    for k, v in qs:
        if k == key:
            new_qs.append((k, value))
        else:
            new_qs.append((k, v))

    new_query = urlencode(new_qs, doseq=True)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


def _find_sql_errors(text: str) -> list[str]:
    matches = []
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matches.append(pat)
    return matches


def detect_sqli_for_url(
    url: str,
    timeout_s: int = 8,
) -> list[dict]:
    """
    Lightweight GET-only SQLi detector.
    Returns list of alerts for suspicious parameters.
    """
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []

    findings = []

    try:
        baseline_resp = requests.get(url, timeout=timeout_s)
        baseline_text = baseline_resp.text
        baseline_len, baseline_hash = _body_signature(baseline_text)
        baseline_errors = _find_sql_errors(baseline_text)
    except Exception:
        return []

    for key, original_value in params:
        key_l = key.lower()

        # Prioritise useful parameter names on larger query strings
        if key_l not in STRONG_PARAM_KEYS and len(params) > 3:
            continue

        # Avoid double-encoding / double-quoting if seed URL already contains quotes
        clean_value = original_value.replace("%27", "").replace("'", "")

        quote_url = _replace_param(url, key, f"{clean_value}'")
        true_url = _replace_param(url, key, f"{clean_value}' OR 1=1-- ")
        false_url = _replace_param(url, key, f"{clean_value}' OR 1=2-- ")

        try:
            quote_resp = requests.get(quote_url, timeout=timeout_s)
            true_resp = requests.get(true_url, timeout=timeout_s)
            false_resp = requests.get(false_url, timeout=timeout_s)
        except Exception:
            continue

        quote_text = quote_resp.text
        true_text = true_resp.text
        false_text = false_resp.text

        quote_len, quote_hash = _body_signature(quote_text)
        true_len, true_hash = _body_signature(true_text)
        false_len, false_hash = _body_signature(false_text)

        quote_errors = _find_sql_errors(quote_text)

        # 1) Error-based detection
        if quote_errors and quote_errors != baseline_errors:
            findings.append(
                {
                    "alert": "SQL Injection (Custom Error Probe)",
                    "name": "SQL Injection (Custom Error Probe)",
                    "risk": "High",
                    "confidence": "High",
                    "url": url,
                    "param": key,
                    "method": "GET",
                    "pluginId": "CUSTOM-SQLI-ERROR",
                    "cweid": "89",
                    "wascid": "19",
                    "description": "A custom SQL error-based probe triggered database error patterns after injecting a single quote.",
                    "solution": "Use parameterised queries / prepared statements and validate input.",
                    "evidence": f"Detected SQL error pattern(s): {quote_errors}",
                    "other": "",
                    "tags": {
                        "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
                        "OWASP_2021_A03": "https://owasp.org/Top10/A03_2021-Injection/",
                    },
                }
            )
            continue

        # 2) Boolean differential detection
        true_vs_false = true_hash != false_hash
        true_vs_baseline = true_hash != baseline_hash
        false_vs_baseline = false_hash != baseline_hash

        if true_vs_false and (true_vs_baseline or false_vs_baseline):
            findings.append(
                {
                    "alert": "SQL Injection (Custom Boolean Probe)",
                    "name": "SQL Injection (Custom Boolean Probe)",
                    "risk": "High",
                    "confidence": "Medium",
                    "url": url,
                    "param": key,
                    "method": "GET",
                    "pluginId": "CUSTOM-SQLI-BOOLEAN",
                    "cweid": "89",
                    "wascid": "19",
                    "description": "A custom boolean SQLi probe produced materially different true/false responses.",
                    "solution": "Use parameterised queries / prepared statements and validate input.",
                    "evidence": (
                        f"True/false differential detected. "
                        f"Baseline length={baseline_len}, true length={true_len}, false length={false_len}"
                    ),
                    "other": "",
                    "tags": {
                        "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
                        "OWASP_2021_A03": "https://owasp.org/Top10/A03_2021-Injection/",
                    },
                }
            )

    return findings
