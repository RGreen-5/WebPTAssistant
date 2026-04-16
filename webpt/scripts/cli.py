# cli.py
# Main entry point for the tool:
# Nmap -> ZAP -> lightweight SQLi detection -> analyst review extraction -> normalize -> enrich -> report

import argparse
import json
import os
from datetime import datetime, UTC
from urllib.parse import urlparse

from zapv2 import ZAPv2

from scripts.core.nmap_runner import run_nmap_all_ports
from scripts.core.zap_runner import zap_fast_scan
from scripts.core.normalize import normalize_zap_alerts
from scripts.core.zap_message_extractor import (
    analyze_zap_messages_for_sqlmap,
    export_requests_to_files,
)
from scripts.core.sqli_detector import detect_sqli_for_url
from scripts.connectors.exploitdb import enrich_with_searchsploit
from scripts.connectors.misp import misp_enrich_groups
from scripts.ai.summarize import ai_summarize_groups
from scripts.reporting.render import render_console_summary, write_markdown_report


def parse_args():
    p = argparse.ArgumentParser(prog="webpt-assistant")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser(
        "scan",
        help="Run Nmap + ZAP + lightweight SQLi detection + analyst review extraction + normalize + enrich + report",
    )
    s.add_argument("--target", required=True, help="Target URL, e.g. http://192.168.56.102/")
    s.add_argument("--zap-proxy", default="http://127.0.0.1:8080", help="ZAP proxy URL")
    s.add_argument("--outdir", default="output", help="Output directory")
    s.add_argument(
        "--exclude",
        action="append",
        default=["/twiki/", "/phpMyAdmin/"],
        help="Path prefix to exclude (repeatable)",
    )
    s.add_argument("--spider-seconds", type=int, default=60)
    s.add_argument("--ascan-seconds", type=int, default=300)
    s.add_argument("--nmap-timeout", type=int, default=1800)
    s.add_argument(
        "--review-top-n",
        type=int,
        default=6,
        help="Number of top-scoring ZAP requests to export for analyst review",
    )
    s.add_argument(
        "--sqli-disable",
        action="store_true",
        help="Disable lightweight custom SQLi detection",
    )

    s.add_argument("--misp-url", default=os.getenv("MISP_URL", ""))
    s.add_argument("--misp-key", default=os.getenv("MISP_KEY", ""))
    s.add_argument("--misp-verify-tls", action="store_true", default=False)

    s.add_argument(
        "--ai-mode",
        choices=["off", "local"],
        default="local",
        help="AI summariser mode",
    )

    return p.parse_args()


def _build_probe_url(target: str, probe: str) -> str:
    probe = (probe or "").strip()
    if probe.startswith("http://") or probe.startswith("https://"):
        return probe
    return f"{target}{probe}"


def main():
    args = parse_args()
    target = args.target.rstrip("/")
    os.makedirs(args.outdir, exist_ok=True)

    u = urlparse(target)
    if not u.scheme or not u.netloc:
        raise SystemExit("Invalid --target. Example: http://192.168.56.102/")

    host = u.hostname
    if not host:
        raise SystemExit("Could not extract host from URL")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    meta = {"run_id": run_id, "target": target, "host": host}

    # 1) Nmap service scan
    print("[1/6] Nmap scan starting...")
    nmap_raw = run_nmap_all_ports(target, timeout_s=args.nmap_timeout)
    with open(os.path.join(args.outdir, "nmap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **nmap_raw}, f, indent=2)
    print("[1/6] Nmap scan completed.")

    # 2) ZAP scan
    print("[2/6] ZAP scan starting, this may take a while...")
    zap_raw = zap_fast_scan(
        target=target,
        zap_proxy=args.zap_proxy,
        exclude_prefixes=args.exclude,
        spider_budget_s=args.spider_seconds,
        ascan_budget_s=args.ascan_seconds,
    )

    with open(os.path.join(args.outdir, "zap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **zap_raw}, f, indent=2)
    print("[2/6] ZAP scan completed.")

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    zap = ZAPv2(apikey="", proxies={"http": args.zap_proxy, "https": args.zap_proxy})

    # 3) Lightweight custom SQLi detection
    print("[3/6] Lightweight SQLi detection starting...")
    sqli_alerts = []

    if not args.sqli_disable:
        try:
            zap_analysis_for_sqli = analyze_zap_messages_for_sqlmap(
                zap,
                base=base,
                top_n=args.review_top_n,
                verbose=False,
                exclude_prefixes=args.exclude,
            )

            top_requests_for_sqli = zap_analysis_for_sqli["top_candidates"]
            get_targets = []

            # Candidate GET URLs already containing parameters
            for msg in top_requests_for_sqli:
                try:
                    parsed_msg = urlparse(msg.url)
                    if msg.method.upper() == "GET" and parsed_msg.query:
                        get_targets.append(msg.url)
                except Exception:
                    continue

            # Use ALL discovered URLs from ZAP to decide whether to add seeded probes
            try:
                all_discovered_urls = zap.core.urls(base)
            except Exception:
                all_discovered_urls = [r.url for r in top_requests_for_sqli]

            # SQLi-Labs seeded probes
            sqli_lab_probes = [
                "/Less-1/?id=1",
                "/Less-2/?id=1",
                "/Less-3/?id=1",
                "/Less-4/?id=1",
                "/Less-5/?id=1",
            ]

            if any("/Less-" in u for u in all_discovered_urls):
                for probe in sqli_lab_probes:
                    probe_url = _build_probe_url(target, probe)
                    if probe_url not in get_targets:
                        get_targets.append(probe_url)

            # Mutillidae seeded probes
            mutillidae_probes = [
                "/index.php?page=user-info.php&username=test%27&password=test%27&user-info-php-submit-button=View+Account+Details",
            ]

            if any(
                marker in " ".join(all_discovered_urls).lower()
                for marker in [
                    "user-info.php",
                    "add-to-your-blog.php",
                    "captured-data.php",
                    "show-log.php",
                    "register.php",
                    "sqlmap-targets.php",
                ]
            ):
                for probe in mutillidae_probes:
                    probe_url = _build_probe_url(target, probe)
                    if probe_url not in get_targets:
                        get_targets.append(probe_url)

            # Deduplicate while preserving order
            get_targets = list(dict.fromkeys(get_targets))

            if get_targets:
                print("     [*] SQLi probe targets:")
                for t in get_targets:
                    print(f"         - {t}")
            else:
                print("     [*] No GET parameterised targets discovered for SQLi probing.")

            for sqli_target in get_targets:
                found = detect_sqli_for_url(sqli_target, timeout_s=8)
                if found:
                    sqli_alerts.extend(found)

            with open(os.path.join(args.outdir, "custom_sqli_alerts.json"), "w", encoding="utf-8") as f:
                json.dump(sqli_alerts, f, indent=2)

            if sqli_alerts:
                zap_raw.setdefault("alerts", [])
                zap_raw["alerts"].extend(sqli_alerts)
                print(f"[3/6] Lightweight SQLi detection completed. Found {len(sqli_alerts)} SQLi signal(s).")
            else:
                print("[3/6] Lightweight SQLi detection completed. No SQLi signals found.")

        except Exception as e:
            print(f"[3/6] Lightweight SQLi detection failed: {e}")
    else:
        print("[3/6] Lightweight SQLi detection skipped (--sqli-disable).")

    # 4) Analyst review candidate extraction
    print("[4/6] Analyst review candidate extraction starting...")
    analyst_review_candidates = []

    print("     [*] Extracting and scoring requests from ZAP history...")
    zap_analysis = analyze_zap_messages_for_sqlmap(
        zap,
        base=base,
        top_n=args.review_top_n,
        verbose=True,
        exclude_prefixes=args.exclude,
    )

    top_requests = zap_analysis["top_candidates"]

    with open(os.path.join(args.outdir, "zap_message_analysis.json"), "w", encoding="utf-8") as f:
        top_req_json = [
            {
                "url": r.url,
                "method": r.method,
                "status_code": r.status_code,
                "score": r.score_for_sqlmap(),
                "has_security_cookie": r.has_security_cookie(),
            }
            for r in top_requests
        ]
        json.dump(
            {
                "total_messages_extracted": zap_analysis["analysis"]["total_messages"],
                "top_selected": len(top_requests),
                "top_requests": top_req_json,
                "analysis": zap_analysis["analysis"],
            },
            f,
            indent=2,
        )

    req_dir = os.path.join(args.outdir, "analyst_review_requests")
    request_files = export_requests_to_files(
        top_requests,
        output_dir=req_dir,
        verbose=True,
    )

    for idx, msg in enumerate(top_requests):
        analyst_review_candidates.append(
            {
                "request_index": idx,
                "url": msg.url,
                "method": msg.method,
                "score": msg.score_for_sqlmap(),
                "status_code": msg.status_code,
                "request_file": request_files[idx],
                "has_security_cookie": msg.has_security_cookie(),
                "reason": "High-value parameterised request extracted from ZAP history for analyst review",
            }
        )

    with open(os.path.join(args.outdir, "analyst_review_candidates.json"), "w", encoding="utf-8") as f:
        json.dump(analyst_review_candidates, f, indent=2)

    print("[4/6] Analyst review candidate extraction completed.")

    # 5) Normalize findings
    print("[5/6] Normalising + enrichment starting...")
    groups, summary = normalize_zap_alerts(zap_raw["alerts"], baseurl=target)
    with open(os.path.join(args.outdir, "zap_groups.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, "summary": summary, "groups": groups}, f, indent=2)
    print("[5/6] Normalising completed.")

    # Threat intel enrichment
    groups = enrich_with_searchsploit(groups, nmap_stdout=nmap_raw.get("stdout", ""))

    if args.misp_url:
        groups = misp_enrich_groups(
            groups,
            misp_url=args.misp_url,
            misp_key=args.misp_key,
            verify_tls=args.misp_verify_tls,
        )

    # 6) AI summary + report
    print("[6/6] AI summary + report generation starting...")
    if args.ai_mode != "off":
        groups, exec_summary = ai_summarize_groups(groups)
    else:
        exec_summary = "AI summarisation disabled."

    render_console_summary(summary, groups, exec_summary)
    write_markdown_report(
        os.path.join(args.outdir, "report.md"),
        meta,
        summary,
        groups,
        exec_summary,
    )

    print("[6/6] Report completed.")
    print(f'Full report can be found at "{args.outdir}/report.md"')


if __name__ == "__main__":
    main()
