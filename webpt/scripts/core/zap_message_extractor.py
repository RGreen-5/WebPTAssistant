from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qsl


STRONG_KEYS = {
    "password", "pass", "pwd",
}
MED_KEYS = {
    "user", "username", "uid", "userid",
    "email", "mail",
    "id", "qid", "pid", "bid",
    "q", "query", "search", "keyword",
    "name", "title",
    "comment", "message", "content",
    "filter", "sort", "order",
    "page", "file", "path", "include",
    "redirect", "return", "next", "url",
}
TOKEN_KEYS = {"token", "csrf", "auth", "nonce", "sess", "phpsessid"}


@dataclass
class ZapMessage:
    message_id: int
    url: str
    method: str
    request_header: str
    request_body: str
    response_header: str
    status_code: int

    def get_cookie_header(self) -> Optional[str]:
        for line in self.request_header.splitlines():
            if line.lower().startswith("cookie:"):
                return line.split(":", 1)[1].strip()
        return None

    def has_security_cookie(self) -> bool:
        cookie = self.get_cookie_header() or ""
        return "security=" in cookie.lower()

    def _param_keys(self) -> List[str]:
        keys: List[str] = []

        try:
            u = urlparse(self.url)
            for k, _v in parse_qsl(u.query, keep_blank_values=True):
                keys.append(k.lower())
        except Exception:
            pass

        body = (self.request_body or "").strip()
        if body and "=" in body:
            try:
                for k, _v in parse_qsl(body, keep_blank_values=True):
                    keys.append(k.lower())
            except Exception:
                pass

        return keys

    def has_interesting_parameter(self) -> bool:
        keys = set(self._param_keys())
        return bool(keys & STRONG_KEYS or keys & MED_KEYS)

    def is_get_with_params(self) -> bool:
        try:
            u = urlparse(self.url)
            return self.method.upper() == "GET" and bool(u.query)
        except Exception:
            return False

    def score_for_sqlmap(self) -> int:
        score = 0
        method = (self.method or "GET").upper()
        url_lower = (self.url or "").lower()
        keys = self._param_keys()
        keyset = set(keys)

        if method == "GET" and keyset:
            score += 30
        elif method == "POST":
            score += 20
        elif method in {"PUT", "PATCH"}:
            score += 15

        if 200 <= self.status_code < 400:
            score += 15
        elif self.status_code >= 400:
            score -= 10

        if keyset & STRONG_KEYS:
            score += 70

        if keyset & MED_KEYS:
            score += 30

        if "page" in keyset:
            score += 20

        if self.has_security_cookie():
            score += 40

        token_hits = sum(1 for k in keys if k in TOKEN_KEYS)
        if token_hits >= 1 and not (keyset & STRONG_KEYS):
            score -= 20

        if any(p in url_lower for p in ["?c=", "?o=", "?c=d", "?o=d"]):
            score -= 30

        if any(url_lower.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".woff", ".ttf"]):
            score -= 40

        return max(0, score)


def _extract_status_code(response_header: str) -> int:
    try:
        first_line = response_header.split("\n", 1)[0]
        parts = first_line.split()
        if len(parts) >= 2:
            return int(parts[1])
    except Exception:
        pass
    return 0


def _is_excluded(url: str, exclude_prefixes: List[str]) -> bool:
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return False

    for pref in exclude_prefixes or []:
        pref = (pref or "").strip().lower().rstrip("*")
        if pref and path.startswith(pref):
            return True
    return False


def extract_zap_messages(
    zap,
    base: str,
    max_messages: int = 500,
    exclude_prefixes: Optional[List[str]] = None,
) -> List[ZapMessage]:
    messages: List[ZapMessage] = []
    start = 0
    page_size = 50

    while start < max_messages:
        try:
            batch = zap.core.messages(baseurl=base, start=start, count=page_size)
            if not batch:
                break

            for msg_dict in batch:
                try:
                    request_header = msg_dict.get("requestHeader", "")
                    header_parts = request_header.split()
                    method = header_parts[0] if header_parts else "GET"
                    url = header_parts[1] if len(header_parts) > 1 else ""

                    if exclude_prefixes and _is_excluded(url, exclude_prefixes):
                        continue

                    msg = ZapMessage(
                        message_id=int(msg_dict.get("id", start)),
                        url=url,
                        method=method,
                        request_header=request_header,
                        request_body=msg_dict.get("requestBody", ""),
                        response_header=msg_dict.get("responseHeader", ""),
                        status_code=_extract_status_code(msg_dict.get("responseHeader", "")),
                    )
                    messages.append(msg)
                except Exception:
                    continue

            if len(batch) < page_size:
                break

            start += page_size
        except Exception:
            break

    return messages


def _dedupe_messages(messages: List[ZapMessage]) -> List[ZapMessage]:
    seen: set[Tuple[str, str]] = set()
    out: List[ZapMessage] = []
    for m in messages:
        key = ((m.method or "GET").upper(), m.url or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out


def select_top_requests(
    messages: List[ZapMessage],
    top_n: int = 10,
    verbose: bool = False,
) -> List[ZapMessage]:
    messages = _dedupe_messages(messages)
    scored = [(msg, msg.score_for_sqlmap()) for msg in messages]
    scored.sort(key=lambda x: x[1], reverse=True)

    if verbose:
        print(f"[*] Scored {len(scored)} messages; top candidates:")
        for msg, score in scored[:min(top_n + 8, len(scored))]:
            print(f"    {score:3d} | {msg.method:6s} {msg.url[:100]}")

    return [msg for msg, _score in scored[:top_n]]


def export_request_file(message: ZapMessage, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    header = message.request_header or ""
    lines = header.splitlines()
    if not lines:
        raise ValueError("Empty request_header from ZAP message")

    parts = lines[0].split()
    if len(parts) < 3:
        raise ValueError(f"Bad request line: {lines[0]!r}")

    method, target, version = parts[0], parts[1], parts[2]

    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        target = path

        has_host = any(l.lower().startswith("host:") for l in lines[1:])
        if not has_host:
            lines.insert(1, f"Host: {parsed.netloc}")

    lines[0] = f"{method} {target} {version}"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")
        if (message.request_body or "").strip():
            f.write("\n")
            f.write(message.request_body)


def export_requests_to_files(
    messages: List[ZapMessage],
    output_dir: str,
    verbose: bool = False,
) -> Dict[int, str]:
    os.makedirs(output_dir, exist_ok=True)
    paths: Dict[int, str] = {}

    for idx, msg in enumerate(messages):
        req_file = os.path.join(output_dir, f"sqlmap_req_{idx}.txt")
        export_request_file(msg, req_file)
        paths[idx] = req_file

        if verbose:
            print(f"[+] Exported request {idx}: {msg.method} {msg.url[:80]}")
            print(f"    → {req_file}")

    return paths


def analyze_zap_messages_for_sqlmap(
    zap,
    base: str,
    top_n: int = 10,
    verbose: bool = True,
    exclude_prefixes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    messages = extract_zap_messages(
        zap,
        base=base,
        max_messages=500,
        exclude_prefixes=exclude_prefixes or [],
    )

    if verbose:
        print(f"[*] Extracted {len(messages)} messages from ZAP history")

    top = select_top_requests(messages, top_n=top_n, verbose=verbose)

    cookies_seen: Dict[str, int] = {}
    methods_seen: Dict[str, int] = {}
    urls_with_interesting = 0

    for msg in messages:
        cookie = msg.get_cookie_header()
        if cookie:
            cookies_seen[cookie] = cookies_seen.get(cookie, 0) + 1
        methods_seen[msg.method] = methods_seen.get(msg.method, 0) + 1
        if msg.has_interesting_parameter():
            urls_with_interesting += 1

    return {
        "total_extracted": len(messages),
        "top_candidates": top,
        "analysis": {
            "total_messages": len(messages),
            "top_n_selected": len(top),
            "cookies_found": len(cookies_seen),
            "most_common_cookies": sorted(cookies_seen.items(), key=lambda x: x[1], reverse=True)[:5],
            "http_methods": methods_seen,
            "messages_with_interesting_params": urls_with_interesting,
        },
    }
