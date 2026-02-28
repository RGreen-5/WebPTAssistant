# sqlmap_runner.py
#
# Purpose:
#   Fast-but-reasonable SQLMap runner intended for *authorised* security testing.
#   Designed to plug into an orchestration pipeline (like your Nmap/ZAP runners),
#   producing a structured dict + parsable findings without hardcoding any target app.
#
# Philosophy:
#   - "Quick" but with decent coverage: uses crawl+forms discovery, moderate level/risk,
#     and a second-pass escalation ONLY for URLs/params that show signs of injection.
#   - Avoids noisy tamper chains by default (analyst-friendly + defensible methodology).
#
# Requirements:
#   - sqlmap installed and in PATH (e.g., `sudo apt install sqlmap` on Kali)
#
# Notes:
#   - SQLMap output is not guaranteed stable as a JSON API without using its API server.
#     This runner parses stdout and (if available) SQLMap output log files.

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse


@dataclass
class SqlmapFinding:
    url: str
    parameter: str
    place: str  # GET/POST/URI/COOKIE/HEADER
    technique: Optional[str] = None  # boolean-based blind/time-based/error-based/UNION etc.
    dbms: Optional[str] = None
    title: Optional[str] = None
    payload: Optional[str] = None
    confidence: str = "High"  # SQLMap "vulnerable" is typically high confidence
    severity: str = "High"
    tool: str = "sqlmap"


_SQLMAP_VULN_RE = re.compile(r"parameter '([^']+)' is vulnerable", re.IGNORECASE)
_SQLMAP_PARAM_BLOCK_START_RE = re.compile(r"^Parameter:\s*(.+?)\s*\((GET|POST|URI|COOKIE|HEADER)\)\s*$", re.IGNORECASE)
_SQLMAP_TYPE_RE = re.compile(r"^\s*Type:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_TITLE_RE = re.compile(r"^\s*Title:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)


def _which_sqlmap() -> str:
    path = shutil.which("sqlmap")
    if path:
        return path
    # Some installs have sqlmap.py only
    path = shutil.which("sqlmap.py")
    if path:
        return path
    raise FileNotFoundError("sqlmap not found in PATH. Install with: sudo apt install sqlmap")


def _safe_mkdir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def _read_text_if_exists(path: str, max_bytes: int = 3_000_000) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _parse_sqlmap_stdout(stdout: str, target_url: str) -> List[SqlmapFinding]:
    """
    Parse SQLMap stdout for confirmed injection blocks.
    SQLMap prints a structured block when it confirms an injectable parameter.
    """
    findings: List[SqlmapFinding] = []

    current_param: Optional[str] = None
    current_place: Optional[str] = None
    current_type: Optional[str] = None
    current_title: Optional[str] = None
    current_payload: Optional[str] = None
    current_dbms: Optional[str] = None

    lines = stdout.splitlines()

    # capture global DBMS lines (sometimes appears outside block)
    for line in lines:
        mdb = _SQLMAP_DBMS_RE.search(line)
        if mdb:
            current_dbms = (mdb.group(1) or "").strip()

    def flush_block():
        nonlocal current_param, current_place, current_type, current_title, current_payload
        if current_param and current_place:
            findings.append(
                SqlmapFinding(
                    url=target_url,
                    parameter=current_param.strip(),
                    place=current_place.strip().upper(),
                    technique=(current_type.strip() if current_type else None),
                    dbms=(current_dbms.strip() if current_dbms else None),
                    title=(current_title.strip() if current_title else None),
                    payload=(current_payload.strip() if current_payload else None),
                )
            )
        current_param = None
        current_place = None
        current_type = None
        current_title = None
        current_payload = None

    for line in lines:
        mstart = _SQLMAP_PARAM_BLOCK_START_RE.match(line)
        if mstart:
            # new block begins; flush previous
            flush_block()
            current_param = mstart.group(1)
            current_place = mstart.group(2)
            continue

        mtype = _SQLMAP_TYPE_RE.match(line)
        if mtype:
            current_type = mtype.group(1)
            continue

        mtitle = _SQLMAP_TITLE_RE.match(line)
        if mtitle:
            current_title = mtitle.group(1)
            continue

        mpay = _SQLMAP_PAYLOAD_RE.match(line)
        if mpay:
            current_payload = mpay.group(1)
            continue

    flush_block()

    # If SQLMap says "parameter 'x' is vulnerable" but doesn't print full blocks,
    # create minimal findings.
    if not findings:
        for line in lines:
            mv = _SQLMAP_VULN_RE.search(line)
            if mv:
                findings.append(
                    SqlmapFinding(
                        url=target_url,
                        parameter=mv.group(1),
                        place="UNKNOWN",
                        dbms=(current_dbms.strip() if current_dbms else None),
                    )
                )

    # Deduplicate (same url/param/place)
    uniq = {}
    for f in findings:
        key = (f.url, f.parameter, f.place, f.technique or "", f.payload or "")
        uniq[key] = f
    return list(uniq.values())


def _build_base_args(
    sqlmap_path: str,
    target_url: str,
    output_dir: str,
    cookie: Optional[str],
    headers: Optional[Dict[str, str]],
    data: Optional[str],
    method: Optional[str],
    timeout_s: int,
    threads: int,
    level: int,
    risk: int,
    crawl: int,
    forms: bool,
    smart: bool,
    random_agent: bool,
    flush_session: bool,
) -> List[str]:
    args = [sqlmap_path, "-u", target_url, "--batch", "--output-dir", output_dir]

    # Discovery knobs
    if crawl and crawl > 0:
        args += ["--crawl", str(crawl)]
    if forms:
        args += ["--forms"]

    # Accuracy/perf knobs
    args += ["--level", str(level), "--risk", str(risk)]
    args += ["--threads", str(max(1, threads))]
    args += ["--timeout", str(max(3, timeout_s))]
    args += ["--retries", "1"]
    args += ["--parse-errors"]

    if smart:
        args += ["--smart"]
    if random_agent:
        args += ["--random-agent"]
    if flush_session:
        args += ["--flush-session"]

    # Request context
    if method:
        args += ["--method", method.upper()]
    if data:
        args += ["--data", data]
    if cookie:
        args += ["--cookie", cookie]
    if headers:
        for k, v in headers.items():
            # sqlmap expects raw header lines
            args += ["--header", f"{k}: {v}"]

    # Make output quieter but still informative
    args += ["-v", "1"]  # keep it low for speed/log size
    return args


def run_sqlmap_quick(
    target_url: str,
    output_dir: str,
    *,
    max_runtime_s: int = 900,
    cookie: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    method: Optional[str] = None,
    # "Quick but doesn't miss things": start moderate, then escalate only when needed.
    threads: int = 4,
    timeout_s: int = 10,
    crawl: int = 2,
    forms: bool = True,
    # Pass-1 settings
    level_1: int = 3,
    risk_1: int = 2,
    # Pass-2 escalation (still controlled)
    level_2: int = 5,
    risk_2: int = 3,
) -> Dict[str, Any]:
    """
    Two-pass SQLMap strategy:
      - Pass 1 (fast coverage): crawl+forms, level 3 risk 2, smart mode
      - Pass 2 (targeted escalation): only if pass-1 indicates possible injection
        or confirms injection but without full technique details.
    """
    _safe_mkdir(output_dir)
    sqlmap_path = _which_sqlmap()

    started = time.time()

    def run_one(pass_name: str, level: int, risk: int, smart: bool) -> Dict[str, Any]:
        args = _build_base_args(
            sqlmap_path=sqlmap_path,
            target_url=target_url,
            output_dir=output_dir,
            cookie=cookie,
            headers=headers,
            data=data,
            method=method,
            timeout_s=timeout_s,
            threads=threads,
            level=level,
            risk=risk,
            crawl=crawl,
            forms=forms,
            smart=smart,
            random_agent=True,
            flush_session=(pass_name == "pass1"),  # keep pass2 incremental
        )

        # Keep remaining time for pass2
        remaining = max(30, max_runtime_s - int(time.time() - started))

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=remaining,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            rc = proc.returncode
        except subprocess.TimeoutExpired as e:
            stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
            stderr = (e.stderr or "") if isinstance(e.stderr, str) else ""
            rc = 124

        findings = _parse_sqlmap_stdout(stdout + "\n" + stderr, target_url)

        # Heuristic: detect “maybe injectable” indicators even if not fully confirmed
        maybe_indicators = any(
            s.lower().find("heuristic") >= 0
            or s.lower().find("might be injectable") >= 0
            or s.lower().find("appears to be injectable") >= 0
            for s in (stdout.splitlines() + stderr.splitlines())
        )

        return {
            "pass": pass_name,
            "cmd": " ".join(shlex.quote(x) for x in args),
            "returncode": rc,
            "stdout_tail": (stdout[-4000:] if stdout else ""),
            "stderr_tail": (stderr[-4000:] if stderr else ""),
            "findings": [asdict(f) for f in findings],
            "maybe_indicators": maybe_indicators,
        }

    # Pass 1
    pass1 = run_one("pass1", level_1, risk_1, smart=True)

    # Decide whether to escalate
    pass1_findings = pass1.get("findings", []) or []
    need_escalation = bool(pass1_findings) or bool(pass1.get("maybe_indicators"))

    pass2 = None
    if need_escalation:
        pass2 = run_one("pass2", level_2, risk_2, smart=False)

    # Combine findings (dedupe)
    combined: Dict[tuple, Dict[str, Any]] = {}
    for f in (pass1_findings + ((pass2 or {}).get("findings", []) or [])):
        key = (f.get("url"), f.get("parameter"), f.get("place"), f.get("technique"), f.get("payload"))
        combined[key] = f

    return {
        "target": target_url,
        "tool": "sqlmap",
        "strategy": {
            "pass1": {"level": level_1, "risk": risk_1, "smart": True, "crawl": crawl, "forms": forms},
            "pass2": {"level": level_2, "risk": risk_2, "smart": False, "crawl": crawl, "forms": forms} if pass2 else None,
            "max_runtime_s": max_runtime_s,
        },
        "passes": [pass1] + ([pass2] if pass2 else []),
        "findings": list(combined.values()),
        "finding_count": len(combined),
        "elapsed_s": int(time.time() - started),
        "output_dir": output_dir,
    }


# Optional convenience wrapper for your pipeline:
# Convert SQLMap findings into a ZAP-like alert object list so your normaliser can ingest it.
def sqlmap_findings_to_alerts(sqlmap_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for f in sqlmap_result.get("findings", []) or []:
        alerts.append(
            {
                "alert": "SQL Injection (SQLMap Confirmed)",
                "name": "SQL Injection (SQLMap Confirmed)",
                "risk": "High",
                "confidence": "High",
                "url": f.get("url", ""),
                "param": f.get("parameter", ""),
                "method": "GET/POST",  # sqlmap output parsing doesn’t always include exact method line
                "pluginId": "SQLMAP",
                "cweid": "89",
                "wascid": "19",
                "description": f"SQLMap confirmed SQL injection. Technique: {f.get('technique') or 'unknown'}.",
                "solution": "Use parameterised queries / prepared statements. Validate input. Apply least privilege DB accounts.",
                "evidence": f"Title: {f.get('title') or ''}\nPayload: {f.get('payload') or ''}\nDBMS: {f.get('dbms') or ''}".strip(),
                "other": "",
                "tags": {
                    "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
                    "OWASP_2021_A03": "https://owasp.org/Top10/A03_2021-Injection/",
                },
            }
        )
    return alerts
