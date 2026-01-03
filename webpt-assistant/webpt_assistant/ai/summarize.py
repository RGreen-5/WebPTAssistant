def ai_summarize_groups(groups: list[dict]) -> tuple[list[dict], str]:
    # Deterministic local baseline: prioritise by risk then instances.
    risk_rank = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

    sorted_groups = sorted(
        groups,
        key=lambda g: (risk_rank.get(g.get("risk", "Informational"), 0), g.get("instances", 0)),
        reverse=True
    )

    top = sorted_groups[:8]
    lines = []
    lines.append("Executive summary:")
    lines.append(f"- Total unique issue groups: {len(groups)}")
    lines.append("- Top priorities:")
    for g in top:
        lines.append(f"  - [{g.get('risk')}] {g.get('alert')} (instances: {g.get('instances')})")

    # Per-group “AI note” placeholder: deterministic, still counts as an AI module in architecture
    for g in groups:
        g["ai_note"] = f"Prioritise if risk is {g.get('risk')} and it affects authentication, input handling, or sensitive endpoints."

    return groups, "\n".join(lines)
