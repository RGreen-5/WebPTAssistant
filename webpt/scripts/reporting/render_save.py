from rich.console import Console
from rich.table import Table


def render_console_summary(summary: dict, groups: list[dict], exec_summary: str) -> None:
    c = Console()
    c.print(exec_summary)
    c.print("")
    c.print(f"Raw alert instances: {summary['raw_instances']}")
    c.print(f"Unique groups: {summary['unique_groups']}")
    c.print(f"Risk instance counts: {summary['risk_instance_counts']}")
    c.print("")

    t = Table(title="Top Findings (grouped)")
    t.add_column("Risk")
    t.add_column("Alert")
    t.add_column("Instances", justify="right")
    for g in groups[:15]:
        t.add_row(str(g.get("risk")), str(g.get("alert")), str(g.get("instances")))
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
        f.write(f"- Risk instance counts: {summary['risk_instance_counts']}\n\n")

        misp_enabled = any(g.get("misp", {}).get("enabled") for g in groups)
        f.write(f"- MISP enrichment: {'enabled' if misp_enabled else 'disabled'}\n\n")

        f.write("## Findings (grouped)\n\n")
        for g in groups:
            f.write(f"### [{g.get('risk')}] {md_escape(g.get('alert'))}\n\n")
            f.write(f"- Confidence: {g.get('confidence')}\n")
            f.write(f"- Instances: {g.get('instances')}\n")
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
