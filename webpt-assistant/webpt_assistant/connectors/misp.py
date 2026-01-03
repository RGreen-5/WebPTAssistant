def misp_enrich_groups(groups: list[dict], misp_url: str, misp_key: str, verify_tls: bool = False) -> list[dict]:
    try:
        from pymisp import PyMISP
    except Exception:
        for g in groups:
            g["misp"] = {"enabled": False, "error": "pymisp not installed"}
        return groups

    try:
        misp = PyMISP(misp_url, misp_key, ssl=verify_tls)
        # lightweight call to validate auth/connectivity
        misp.servers_get_version()
    except Exception as e:
        for g in groups:
            g["misp"] = {"enabled": True, "error": f"MISP unavailable: {e}"}
        return groups

    import re
    for g in groups:
        alert = g.get("alert", "")
        query = None
        m = re.search(r"(CVE-\d{4}-\d{4,7})", alert, re.IGNORECASE)
        if m:
            query = m.group(1).upper()
        elif g.get("cweid") and str(g["cweid"]).isdigit() and int(g["cweid"]) > 0:
            query = f"CWE-{g['cweid']}"
        else:
            query = alert

        try:
            res = misp.search_index(q=query)
            hits = len(res) if isinstance(res, list) else (res.get("count") if isinstance(res, dict) else 0)
            g["misp"] = {"enabled": True, "query": query, "hits": hits}
        except Exception as e:
            g["misp"] = {"enabled": True, "query": query, "error": str(e)}

    return groups

