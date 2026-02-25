from rich.console import Console
from rich.table import Table


def render_console_summary(summary: dict, groups: list[dict], exec_summary: str) -> None:
    c = Console()
    c.print(exec_summary)
    c.print("")
    c.print(f"Raw alert instances: {summary['raw_instances']}")
    c.print(f"Unique groups: {summary['unique_groups']}")

    # New: your exploitability model counts
    if "exploitability_instance_counts" in summary:
        c.print(f"Exploitability instance counts: {summary['exploitability_instance_counts']}")

    # Keep ZAP's original risk counts for transparency (if available)
    if "zap_risk_instance_counts" in summary:
        c.print(f"ZAP risk instance counts: {summary['zap_risk_instance_counts']}")
    elif "risk_instance_counts" in summary:
        # Backwards compatibility if you run older normalize.py
        c.print(f"Risk instance counts: {summary['risk_instance_counts']}")

    c.print("")

    t = Table(title="Top Findings (grouped)")
    t.add_column("Exploitability", no_wrap=True)
    t.add_column("ZAP Risk", no_wrap=True)
    t.add_column("Alert", overflow="fold", no_wrap=False)
    t.add_column("Instances", justify="right", no_wrap=True)

    for g in groups[:15]:
        t.add_row(
            str(g.get("exploitability", "Informational")),
            str(g.get("risk")),
            str(g.get("alert")),
            str(g.get("instances")),
        )
    c.print(t)


def write_markdown_report(path: str, meta: dict, summary: dict, groups: list[dict], exec_summary: str) -> None:
    def md_escape(s):
        return (s or "").replace("\n", " ").strip()

    with open(path, "w", encoding="utf-8") as f:
        f.write("# WebPT Assistant Report\n\n")
        f.write(f"Target: {meta['target']}\n\n")
        f.write("## Executive summary\n\n")
        f.write("```text\n" + exec_summary + "\n```\n\n")

        f.write("## Scan stats\n\n")
        f.write(f"- Raw alert instances: {summary['raw_instances']}\n")
        f.write(f"- Unique issue groups: {summary['unique_groups']}\n")

        # New counts
        if "exploitability_instance_counts" in summary:
            f.write(f"- Exploitability instance counts: {summary['exploitability_instance_counts']}\n")
        if "zap_risk_instance_counts" in summary:
            f.write(f"- ZAP risk instance counts: {summary['zap_risk_instance_counts']}\n")
        elif "risk_instance_counts" in summary:
            # Backwards compatibility
            f.write(f"- Risk instance counts: {summary['risk_instance_counts']}\n")

        f.write("\n")

        misp_enabled = any(g.get("misp", {}).get("enabled") for g in groups)
        f.write(f"- MISP enrichment: {'enabled' if misp_enabled else 'disabled'}\n\n")

        f.write("## Findings (grouped)\n\n")
        for g in groups:
            exploitability = g.get("exploitability", "Informational")
            zap_risk = g.get("risk", "Unknown")
            alert_name = md_escape(g.get("alert"))

            # New heading shows your classification + keeps ZAP risk
            f.write(f"### [{exploitability}] {alert_name}\n\n")
            f.write(f"- ZAP risk: {zap_risk}\n")
            f.write(f"- Confidence: {g.get('confidence')}\n")
            f.write(f"- Instances: {g.get('instances')}\n")

            # Optional plain-English interpretation if present
            interp = g.get("interpretation")
            if interp:
                f.write(f"- What it means: {md_escape(interp.get('risk_explanation'))}\n")
                f.write(f"- Security impact: {md_escape(interp.get('security_impact'))}\n")
                f.write(f"- Recommended action: {md_escape(interp.get('recommended_action'))}\n")

            if g.get("cweid"):
                f.write(f"- CWE: {g.get('cweid')}\n")
            if g.get("wascid"):
                f.write(f"- WASC: {g.get('wascid')}\n")

            if g.get("examples"):
                f.write("- Example endpoints:\n")
                for ex in g["examples"]:
                    f.write(f"  - {ex.get('url_key')} (param: {ex.get('param')}, method: {ex.get('method')})\n")

            hits = g.get("exploitdb", {}).get("hits", [])
            if hits:
                f.write("- ExploitDB (searchsploit) hits:\n")
                for h in hits[:5]:
                    f.write(f"  - {md_escape(h.get('title'))} ({h.get('path')})\n")

            misp = g.get("misp", {})
            if misp.get("enabled"):
                if "error" in misp:
                    f.write(f"- MISP: error: {md_escape(misp['error'])}\n")
                else:
                    f.write(f"- MISP: hits: {misp.get('hits')}, query: {md_escape(misp.get('query'))}\n")

            f.write("\n")
