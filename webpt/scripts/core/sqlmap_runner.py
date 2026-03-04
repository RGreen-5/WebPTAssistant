# sqlmap_runner.py (UPDATED VERSION)
#
# This file runs SQLMap to find SQL injections.
# NEW: It now supports reading from request files (-r mode) which is MUCH better
# because it preserves cookies, POST bodies, and all the context ZAP gathered

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
    """This represents one SQL injection that SQLMap found"""
    url: str
    parameter: str
    place: str  # GET/POST/URI/COOKIE/HEADER
    technique: Optional[str] = None  # boolean-based blind/time-based/error-based/UNION etc.
    dbms: Optional[str] = None  # What database? MySQL? PostgreSQL?
    title: Optional[str] = None
    payload: Optional[str] = None
    confidence: str = "High"
    severity: str = "High"
    tool: str = "sqlmap"


_SQLMAP_VULN_RE = re.compile(r"parameter '([^']+)' is vulnerable", re.IGNORECASE)
_SQLMAP_PARAM_BLOCK_START_RE = re.compile(r"^Parameter:\s*(.+?)\s*\((GET|POST|URI|COOKIE|HEADER)\)\s*$", re.IGNORECASE)
_SQLMAP_TYPE_RE = re.compile(r"^\s*Type:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_TITLE_RE = re.compile(r"^\s*Title:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+?)\s*$", re.IGNORECASE)
_SQLMAP_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)


def _which_sqlmap() -> str:
    """Find where SQLMap is installed"""
    path = shutil.which("sqlmap")
    if path:
        return path
    path = shutil.which("sqlmap.py")
    if path:
        return path
    raise FileNotFoundError("sqlmap not found in PATH. Install with: sudo apt install sqlmap")


def _safe_mkdir(p: str) -> None:
    """Create directory if it doesn't exist"""
    os.makedirs(p, exist_ok=True)


def _parse_sqlmap_stdout(stdout: str, target_url: str) -> List[SqlmapFinding]:
    """
    Read the output from SQLMap and extract what it found.
    SQLMap prints blocks like:
    
    Parameter: password (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind...
    Payload: ' AND 1234=1234 AND '
    
    We parse these blocks and create SqlmapFinding objects.
    """
    findings: List[SqlmapFinding] = []

    current_param: Optional[str] = None
    current_place: Optional[str] = None
    current_type: Optional[str] = None
    current_title: Optional[str] = None
    current_payload: Optional[str] = None
    current_dbms: Optional[str] = None

    lines = stdout.splitlines()

    # Capture global DBMS info
    for line in lines:
        mdb = _SQLMAP_DBMS_RE.search(line)
        if mdb:
            current_dbms = (mdb.group(1) or "").strip()

    def flush_block():
        """Save the current parameter block"""
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

    # Remove duplicates
    uniq = {}
    for f in findings:
        key = (f.url, f.parameter, f.place, f.technique or "", f.payload or "")
        uniq[key] = f
    return list(uniq.values())


def _build_base_args(
    sqlmap_path: str,
    target_url: Optional[str] = None,
    request_file: Optional[str] = None,
    output_dir: str = "",
    cookie: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    method: Optional[str] = None,
    timeout_s: int = 10,
    threads: int = 4,
    level: int = 3,
    risk: int = 2,
    crawl: int = 2,
    forms: bool = True,
    smart: bool = True,
    random_agent: bool = True,
    flush_session: bool = False,
) -> List[str]:
    """
    Build the command line arguments for SQLMap.
    NEW: Supports either -u URL (old way) OR -r request_file (new way, better)
    """
    args = [sqlmap_path, "--batch", "--output-dir", output_dir]

    # NEW: Use request file if available (this is BETTER)
    if request_file and os.path.exists(request_file):
        args += ["-r", request_file]
        # Request file mode already includes method, data, cookies, everything
    elif target_url:
        # OLD: URL mode (still supported for backward compatibility)
        args += ["-u", target_url]
        
        # These only matter in -u mode
        if crawl and crawl > 0:
            args += ["--crawl", str(crawl)]
        if forms:
            args += ["--forms"]
    else:
        raise ValueError("Either target_url or request_file must be provided")

    # These settings apply to BOTH modes
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

    # These only matter in -u mode
    if not request_file or not os.path.exists(request_file):
        if method:
            args += ["--method", method.upper()]
        if data:
            args += ["--data", data]
        if cookie:
            args += ["--cookie", cookie]
        if headers:
            for k, v in headers.items():
                args += ["--header", f"{k}: {v}"]

    args += ["-v", "1"]
    return args


def run_sqlmap_quick(
    target_url: Optional[str] = None,
    request_file: Optional[str] = None,
    output_dir: str = "/tmp/sqlmap_output",
    *,
    max_runtime_s: int = 900,
    cookie: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    method: Optional[str] = None,
    threads: int = 4,
    timeout_s: int = 10,
    crawl: int = 2,
    forms: bool = True,
    level_1: int = 3,
    risk_1: int = 2,
    level_2: int = 5,
    risk_2: int = 3,
) -> Dict[str, Any]:
    """
    Run SQLMap with a smart two-pass strategy:
    
    Pass 1 (fast): --level=3 --risk=2
      - Tests basic SQL injection
      - Takes 2-5 minutes
      - Catches 90% of injections
    
    Pass 2 (thorough): --level=5 --risk=3
      - Only if Pass 1 found something promising
      - Takes 2-5 minutes more
      - Catches difficult blind injections
    
    USAGE:
    - Old way: run_sqlmap_quick(target_url="http://target.com?id=1")
    - New way (BETTER): run_sqlmap_quick(request_file="/tmp/req.txt")
    """
    if not target_url and not request_file:
        raise ValueError("Either target_url or request_file must be provided")

    _safe_mkdir(output_dir)
    sqlmap_path = _which_sqlmap()

    mode = "request_file" if (request_file and os.path.exists(request_file)) else "target_url"
    effective_target = request_file if mode == "request_file" else target_url

    started = time.time()

    def run_one(pass_name: str, level: int, risk: int, smart: bool) -> Dict[str, Any]:
        """Run one pass of SQLMap"""
        args = _build_base_args(
            sqlmap_path=sqlmap_path,
            target_url=target_url if mode == "target_url" else None,
            request_file=request_file if mode == "request_file" else None,
            output_dir=output_dir,
            cookie=cookie if mode == "target_url" else None,
            headers=headers if mode == "target_url" else None,
            data=data if mode == "target_url" else None,
            method=method if mode == "target_url" else None,
            timeout_s=timeout_s,
            threads=threads,
            level=level,
            risk=risk,
            crawl=crawl,
            forms=forms,
            smart=smart,
            random_agent=True,
            flush_session=(pass_name == "pass1"),
        )

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

        findings = _parse_sqlmap_stdout(stdout + "\n" + stderr, effective_target)

        maybe_indicators = any(
            s.lower().find("heuristic") >= 0
            or s.lower().find("might be injectable") >= 0
            or s.lower().find("appears to be injectable") >= 0
            for s in (stdout.splitlines() + stderr.splitlines())
        )

        return {
            "pass": pass_name,
            "mode": mode,
            "cmd": " ".join(shlex.quote(x) for x in args),
            "returncode": rc,
            "stdout_tail": (stdout[-4000:] if stdout else ""),
            "stderr_tail": (stderr[-4000:] if stderr else ""),
            "findings": [asdict(f) for f in findings],
            "maybe_indicators": maybe_indicators,
        }

    # Pass 1: Fast and smart
    pass1 = run_one("pass1", level_1, risk_1, smart=True)

    # Decide if we need Pass 2
    pass1_findings = pass1.get("findings", []) or []
    need_escalation = bool(pass1_findings) or bool(pass1.get("maybe_indicators"))

    pass2 = None
    if need_escalation:
        pass2 = run_one("pass2", level_2, risk_2, smart=False)

    # Combine findings
    combined: Dict[tuple, Dict[str, Any]] = {}
    for f in (pass1_findings + ((pass2 or {}).get("findings", []) or [])):
        key = (f.get("url"), f.get("parameter"), f.get("place"), f.get("technique"), f.get("payload"))
        combined[key] = f

    return {
        "target": effective_target,
        "mode": mode,
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


def sqlmap_findings_to_alerts(sqlmap_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert SQLMap findings into the same format that ZAP alerts use.
    This way they can be combined with other findings in your report.
    """
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
                "method": "GET/POST",
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
