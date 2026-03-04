# zap_message_extractor.py
#
# This file extracts the actual requests that ZAP tested from its history
# Think of it like: ZAP keeps a record of everything it tested, we're just
# reading that record and picking the best candidates for SQLMap

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode


@dataclass
class ZapMessage:
    """
    This represents ONE HTTP request that ZAP tested.
    It contains everything: the URL, the method (GET/POST), headers, cookies, body, etc.
    """
    message_id: int
    url: str
    method: str
    request_header: str
    request_body: str
    response_header: str
    response_body: str
    status_code: int

    def has_interesting_parameter(self) -> bool:
        """
        Check if this request has interesting things like:
        - password field
        - user field
        - search field
        - etc.
        
        These are things that are likely to be vulnerable to SQL injection
        """
        content = (self.url + self.request_body).lower()
        keywords = [
            "password", "pwd", "pass",
            "user", "username", "uid", "userid",
            "email", "mail",
            "id", "qid", "pid", "bid",
            "q", "query", "search", "keyword",
            "token", "csrf", "auth",
            "redirect", "return", "next", "url",
            "name", "title",
            "comment", "message", "content",
            "filter", "sort", "order",
        ]
        return any(kw in content for kw in keywords)

    def get_cookie_header(self) -> Optional[str]:
        """Extract the Cookie line from the request headers"""
        for line in self.request_header.splitlines():
            if line.lower().startswith("cookie:"):
                return line.split(":", 1)[1].strip()
        return None

    def score_for_sqlmap(self) -> int:
        """
        Give this request a score. Higher score = more likely to have SQL injection.
        
        Scoring rules:
        - POST requests are interactive (user filled out a form) = +50 points
        - Has interesting parameters (password, user, search, etc.) = +30 points
        - Has a body (form data) = +20 points
        - Server said OK (200-399 response) = +15 points
        - BUT: Directory listings and static files lose points
        """
        score = 0

        # HTTP method: POST is more interactive than GET
        if self.method.upper() == "POST":
            score += 50
        elif self.method.upper() in ["PUT", "PATCH"]:
            score += 30

        # Parameter presence: does it have interesting field names?
        if self.has_interesting_parameter():
            score += 30

        # Request body: suggests a form was submitted
        if self.request_body.strip():
            score += 20

        # Response status: 2xx/3xx means the request worked
        if 200 <= self.status_code < 400:
            score += 15

        # Penalize obvious non-injection URLs
        url_lower = self.url.lower()

        # Directory listing artifacts (C=D;O=D is Apache directory sorting)
        if any(p in url_lower for p in ["?c=", "?o=", "?c=d", "?o=d"]):
            score -= 20

        # Static files (images, stylesheets, etc.)
        if any(url_lower.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".woff", ".ttf"]):
            score -= 30

        return max(0, score)


def extract_zap_messages(zap, base: str, max_messages: int = 5000) -> List[ZapMessage]:
    """
    This function asks ZAP: "Give me all the requests you tested"
    Then we convert them into ZapMessage objects
    """
    messages = []
    start = 0
    page_size = 100

    while start < max_messages:
        try:
            # Ask ZAP for 100 messages starting at position 'start'
            batch = zap.core.messages(baseurl=base, start=start, count=page_size)
            if not batch:
                break

            for msg_dict in batch:
                try:
                    # Extract the URL from the request header
                    # The first line of a request is like: "GET /path HTTP/1.1"
                    request_header = msg_dict.get("requestHeader", "")
                    header_lines = request_header.split()
                    
                    if len(header_lines) > 1:
                        url = header_lines[1]
                    else:
                        url = ""
                    
                    method = header_lines[0] if header_lines else "GET"

                    msg = ZapMessage(
                        message_id=msg_dict.get("id", start),
                        url=url,
                        method=method,
                        request_header=request_header,
                        request_body=msg_dict.get("requestBody", ""),
                        response_header=msg_dict.get("responseHeader", ""),
                        response_body=msg_dict.get("responseBody", ""),
                        status_code=_extract_status_code(msg_dict.get("responseHeader", "")),
                    )
                    messages.append(msg)
                except Exception:
                    # Skip messages that are broken
                    continue

            if len(batch) < page_size:
                break

            start += page_size
        except Exception:
            # If ZAP connection breaks, return what we have
            break

    return messages


def _extract_status_code(response_header: str) -> int:
    """
    Extract the status code (200, 404, etc.) from the first line of the response.
    First line looks like: "HTTP/1.1 200 OK"
    """
    try:
        first_line = response_header.split("\n")[0]
        parts = first_line.split()
        if len(parts) >= 2:
            return int(parts[1])
    except Exception:
        pass
    return 0


def select_top_requests(
    messages: List[ZapMessage],
    top_n: int = 10,
    verbose: bool = False,
) -> List[ZapMessage]:
    """
    Score all requests and return the top 10 (or top_n)
    Verbose means "print what we're doing"
    """
    # Filter out obvious garbage (static files, etc.)
    candidates = []
    for msg in messages:
        url_lower = msg.url.lower()
        # Skip obvious non-functional URLs
        if any(x in url_lower for x in [".jpg", ".png", ".gif", ".css", ".js", ".ico", ".woff"]):
            continue
        candidates.append(msg)

    # Score and sort
    scored = [(msg, msg.score_for_sqlmap()) for msg in candidates]
    scored.sort(key=lambda x: x[1], reverse=True)

    if verbose:
        print(f"[*] Scored {len(scored)} messages; top candidates:")
        for msg, score in scored[:min(top_n + 5, len(scored))]:
            print(f"    {score:3d} | {msg.method:6s} {msg.url[:80]}")

    return [msg for msg, _score in scored[:top_n]]


def export_request_file(
    message: ZapMessage,
    output_path: str,
    include_body: bool = True,
) -> None:
    """
    Export ONE message to a file that SQLMap can read.
    
    The file format is just a normal HTTP request:
    GET /path HTTP/1.1
    Host: example.com
    Cookie: session=123
    
    [optional POST body]
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        # Write the request header (which includes method, path, headers, etc.)
        f.write(message.request_header)

        # Add blank line before body if there is one
        if include_body and message.request_body.strip():
            f.write("\n")
            f.write(message.request_body)


def export_requests_to_files(
    messages: List[ZapMessage],
    output_dir: str,
    verbose: bool = False,
) -> Dict[str, str]:
    """
    Export MULTIPLE messages to files.
    Returns a dictionary like: {0: "/tmp/sqlmap_req_0.txt", 1: "/tmp/sqlmap_req_1.txt", ...}
    """
    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    for idx, msg in enumerate(messages):
        req_file = os.path.join(output_dir, f"sqlmap_req_{idx}.txt")
        export_request_file(msg, req_file)
        paths[idx] = req_file

        if verbose:
            print(f"[+] Exported request {idx}: {msg.method} {msg.url[:60]}")
            print(f"    → {req_file}")

    return paths


def analyze_zap_messages_for_sqlmap(
    zap,
    base: str,
    top_n: int = 10,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    This is the "easy button" - does everything in one function:
    1. Extract messages from ZAP
    2. Score them
    3. Pick the top N
    4. Return the results + analysis
    """
    messages = extract_zap_messages(zap, base=base, max_messages=5000)

    if verbose:
        print(f"[*] Extracted {len(messages)} messages from ZAP history")

    top = select_top_requests(messages, top_n=top_n, verbose=verbose)

    # Analysis: what cookies did we find? what methods?
    cookies_seen = {}
    methods_seen = {}
    params_seen = {}

    for msg in messages:
        cookie = msg.get_cookie_header()
        if cookie:
            cookies_seen[cookie] = cookies_seen.get(cookie, 0) + 1
        methods_seen[msg.method] = methods_seen.get(msg.method, 0) + 1
        if msg.has_interesting_parameter():
            params_seen[msg.url] = True

    return {
        "total_extracted": len(messages),
        "top_candidates": top,
        "analysis": {
            "total_messages": len(messages),
            "top_n_selected": len(top),
            "cookies_found": len(cookies_seen),
            "most_common_cookies": sorted(
                cookies_seen.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "http_methods": methods_seen,
            "urls_with_interesting_params": len(params_seen),
        },
    }
