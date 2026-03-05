# cli.py - Your main entry point
# This file runs the whole scan: nmap + zap + sqlmap + report

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
from scripts.connectors.exploitdb import enrich_with_searchsploit
from scripts.connectors.misp import misp_enrich_groups
from scripts.ai.summarize import ai_summarize_groups
from scripts.reporting.render import render_console_summary, write_markdown_report
from scripts.core.sqlmap_runner import run_sqlmap_quick, sqlmap_findings_to_alerts

def parse_args():
    p = argparse.ArgumentParser(prog="webpt-assistant")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Run nmap + zap fast scan + normalize + enrich + report")
    s.add_argument("--target", required=True, help="Target URL, e.g. http://192.168.56.102/")
    s.add_argument("--zap-proxy", default="http://127.0.0.1:8080", help="ZAP proxy URL")
    s.add_argument("--outdir", default="output", help="Output directory")
    s.add_argument("--exclude", action="append", default=["/twiki/", "/phpMyAdmin/"], help="Path prefix to exclude (repeatable)")
    s.add_argument("--spider-seconds", type=int, default=120)
    s.add_argument("--ascan-seconds", type=int, default=600)
    s.add_argument("--nmap-timeout", type=int, default=1800)

    # NEW ARGUMENTS for better control
    s.add_argument("--sqlmap-top-n", type=int, default=3,
                   help="Number of top-scoring requests from ZAP to test with SQLMap")
    s.add_argument("--sqlmap-max-runtime", type=int, default=300,
                   help="Max runtime per SQLMap request (seconds)")
    s.add_argument("--sqlmap-disable", action="store_true",
                   help="Skip SQLMap verification entirely")

    s.add_argument("--misp-url", default=os.getenv("MISP_URL", ""))
    s.add_argument("--misp-key", default=os.getenv("MISP_KEY", ""))
    s.add_argument("--misp-verify-tls", action="store_true", default=False)

    s.add_argument("--ai-mode", choices=["off", "local"], default="local",
                   help="AI summariser mode. Use local baseline for now.")

    return p.parse_args()

def main():
    args = parse_args()
    target = args.target
    os.makedirs(args.outdir, exist_ok=True)

    u = urlparse(target)
    if not u.scheme or not u.netloc:
        raise SystemExit("Invalid --target. Example: http://192.168.56.102/")

    host = u.hostname
    if not host:
        raise SystemExit("Could not extract host from URL")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    meta = {"run_id": run_id, "target": target, "host": host}

    # 1) Nmap
    print("[1/5] Nmap scan starting...")
    nmap_raw = run_nmap_all_ports(host, timeout_s=args.nmap_timeout)
    with open(os.path.join(args.outdir, "nmap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **nmap_raw}, f, indent=2)
    print("[1/5] Nmap scan completed.")

    # 2) ZAP fast scan
    print("[2/5] ZAP scan starting, this may take a while...")
    zap_raw = zap_fast_scan(
        target=target,
        zap_proxy=args.zap_proxy,
        exclude_prefixes=args.exclude,
        spider_budget_s=args.spider_seconds,
        ascan_budget_s=args.ascan_seconds,
    )

    # Save ZAP raw immediately
    with open(os.path.join(args.outdir, "zap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **zap_raw}, f, indent=2)
    print("[2/5] ZAP scan completed.")

    # 3) SQLMap verification (NEW: from ZAP message history)
    print("[3/5] SQLMap verification starting...")
    
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    zap = ZAPv2(apikey="", proxies={"http": args.zap_proxy, "https": args.zap_proxy})

    sqlmap_runs = []
    sqlmap_alerts = []

    if not args.sqlmap_disable:
        # NEW: Extract high-value requests from ZAP message history
        print("     [*] Extracting and scoring requests from ZAP history...")
        zap_analysis = analyze_zap_messages_for_sqlmap(
            zap, base=base, top_n=args.sqlmap_top_n, verbose=True
        )
        top_requests = zap_analysis["top_candidates"]

        print(f"     [*] Selected {len(top_requests)} top-scoring requests for SQLMap testing")

        # NEW: Export requests to raw HTTP files
        sqlmap_req_dir = os.path.join(args.outdir, "sqlmap_requests")
        request_files = export_requests_to_files(
            top_requests, output_dir=sqlmap_req_dir, verbose=True
        )

        # Save ZAP analysis for debugging
        with open(os.path.join(args.outdir, "zap_message_analysis.json"), "w", encoding="utf-8") as f:
            top_req_json = [
                {
                    "url": r.url,
                    "method": r.method,
                    "status_code": r.status_code,
                    "score": r.score_for_sqlmap(),
                }
                for r in top_requests
            ]
            json.dump({
                "total_messages_extracted": zap_analysis["analysis"]["total_messages"],
                "top_selected": len(top_requests),
                "top_requests": top_req_json,
                "analysis": zap_analysis["analysis"],
            }, f, indent=2)
        print(f"     [+] Saved ZAP message analysis to zap_message_analysis.json")

        # NEW: Run SQLMap on each request file
        for idx, (req_idx, req_file) in enumerate(request_files.items()):
            print(f"     [*] SQLMap pass {idx + 1}/{len(request_files)}: {top_requests[req_idx].url[:60]}")

            per_url_outdir = os.path.join(args.outdir, "sqlmap", f"request_{req_idx}")

            try:
                sqlmap_res = run_sqlmap_quick(
                    request_file=req_file,  # NEW: use request file instead of URL
                    output_dir=per_url_outdir,
                    max_runtime_s=args.sqlmap_max_runtime,
                    level_1=3,
                    risk_1=2,
                    level_2=5,
                    risk_2=3,
                    crawl=0,
                    forms=False,
                )

                sqlmap_runs.append(sqlmap_res)
                sqlmap_alerts.extend(sqlmap_findings_to_alerts(sqlmap_res))

                # Save intermediate results
                with open(os.path.join(args.outdir, "sqlmap_raw.json"), "w", encoding="utf-8") as f:
                    json.dump(sqlmap_runs, f, indent=2)
                with open(os.path.join(args.outdir, "sqlmap_alerts.json"), "w", encoding="utf-8") as f:
                    json.dump(sqlmap_alerts, f, indent=2)

                # Stop early if SQLi confirmed
                if sqlmap_res.get("finding_count", 0) > 0:
                    print(f"     [+] SQLMap found {sqlmap_res['finding_count']} injection(s). Stopping early.")
                    break

            except Exception as e:
                print(f"     [!] Error running SQLMap on request {req_idx}: {e}")
                continue

        print("[3/5] SQLMap verification completed.")
    else:
        print("[3/5] SQLMap verification skipped (--sqlmap-disable).")

    # 4) Normalize ZAP findings
    print("[4/5] Normalising + enrichment starting...")
    groups, summary = normalize_zap_alerts(zap_raw["alerts"], baseurl=target)
    with open(os.path.join(args.outdir, "zap_groups.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, "summary": summary, "groups": groups}, f, indent=2)
    print("[4/5] Normalising completed.")

    # 5) Threat intel: ExploitDB (local searchsploit)
    groups = enrich_with_searchsploit(groups, nmap_stdout=nmap_raw.get("stdout", ""))

    # 6) Threat intel: MISP (optional)
    if args.misp_url:
        groups = misp_enrich_groups(
            groups,
            misp_url=args.misp_url,
            misp_key=args.misp_key,
            verify_tls=args.misp_verify_tls,
        )

    # 7) AI summary
    print("[5/5] AI summary + report generation starting...")
    if args.ai_mode != "off":
        groups, exec_summary = ai_summarize_groups(groups)
    else:
        exec_summary = "AI summarisation disabled."
    print("[5/5] Report completed.")

    # 8) Report
    render_console_summary(summary, groups, exec_summary)
    write_markdown_report(os.path.join(args.outdir, "report.md"), meta, summary, groups, exec_summary)
    print(f'Full report can be found at "{args.outdir}/report.md"')

if __name__ == "__main__":
    main()
