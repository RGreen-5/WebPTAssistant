import argparse
import json
import os
from datetime import datetime, UTC
from urllib.parse import urlparse

from webpt_assistant.core.nmap_runner import run_nmap_all_ports
from webpt_assistant.core.zap_runner import zap_fast_scan
from webpt_assistant.core.normalize import normalize_zap_alerts
from webpt_assistant.connectors.exploitdb import enrich_with_searchsploit
from webpt_assistant.connectors.misp import misp_enrich_groups
from webpt_assistant.ai.summarize import ai_summarize_groups
from webpt_assistant.reporting.render import render_console_summary, write_markdown_report


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

    s.add_argument("--misp-url", default=os.getenv("MISP_URL", ""))
    s.add_argument("--misp-key", default=os.getenv("MISP_KEY", ""))
    s.add_argument("--misp-verify-tls", action="store_true", default=False)

    s.add_argument("--ai-mode", choices=["off", "local"], default="local",
                   help="AI summariser mode. Use local baseline for now.")

    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    u = urlparse(args.target)
    if not u.scheme or not u.netloc:
        raise SystemExit("Invalid --target. Example: http://192.168.56.102/")

    host = u.hostname
    if not host:
        raise SystemExit("Could not extract host from URL")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    meta = {"run_id": run_id, "target": args.target, "host": host}

    # 1) Nmap
    print("[1/4] Nmap scan starting...")
    nmap_raw = run_nmap_all_ports(host, timeout_s=args.nmap_timeout)
    with open(os.path.join(args.outdir, "nmap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **nmap_raw}, f, indent=2)
    print("[1/4] Nmap scan completed.")


    # 2) ZAP fast scan
    print("[2/4] ZAP fast scan starting...")
    zap_raw = zap_fast_scan(
        target=args.target,
        zap_proxy=args.zap_proxy,
        exclude_prefixes=args.exclude,
        spider_budget_s=args.spider_seconds,
        ascan_budget_s=args.ascan_seconds,
    )
    with open(os.path.join(args.outdir, "zap_raw.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, **zap_raw}, f, indent=2)
    print("[2/4] ZAP fast scan completed.")

    # 3) Normalize
    print("[3/4] Normalising + enrichment starting...")
    groups, summary = normalize_zap_alerts(zap_raw["alerts"], baseurl=args.target)
    with open(os.path.join(args.outdir, "zap_groups.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, "summary": summary, "groups": groups}, f, indent=2)
    print("[3/4] Normalising + enrichment completed.")

    # 4) Threat intel: ExploitDB (local searchsploit)
    groups = enrich_with_searchsploit(groups, nmap_stdout=nmap_raw.get("stdout", ""))

    # 5) Threat intel: MISP (optional)
    if args.misp_url:
   	 groups = misp_enrich_groups(
        	groups,
        	misp_url=args.misp_url,
        	misp_key=args.misp_key,
         	verify_tls=args.misp_verify_tls
   	)

    # 6) AI summary (local baseline)
    print("[4/4] AI summary + report generation starting...")
    if args.ai_mode != "off":
        groups, exec_summary = ai_summarize_groups(groups)
    else:
        exec_summary = "AI summarisation disabled."
    print("[4/4] Report completed.")

    # 7) Report
    render_console_summary(summary, groups, exec_summary)
    write_markdown_report(os.path.join(args.outdir, "report.md"), meta, summary, groups, exec_summary)

    print(f"Wrote: {args.outdir}/report.md")


if __name__ == "__main__":
    main()
