"""Vulnerability taxonomy: HackerOne weakness names -> classes.

Written for this project from the public weakness names themselves (the CWE
titles and OWASP categories HackerOne uses). It is not derived from any other
project's code.

Two layers:
  1. CLASSES    - which class a weakness belongs to, by keyword.
  2. TITLE_RULES - the closest standard weakness name, guessed from a report
                   title when the program filed it without one.

Order matters: the list is scanned top to bottom and the first match wins, so
the specific classes sit above the broad ones.
"""
from __future__ import annotations

import re

# Each class: id, display name, what it covers, and the keywords that mark it.
CLASSES = [
    {"id": "XSS", "name": "Cross-Site Scripting",
     "desc": "Script injected into a page another user views: stored, reflected or DOM.",
     "re": re.compile(r"cross[- ]site scripting|\bxss\b|script injection|html injection", re.I)},
    {"id": "CSRF", "name": "Cross-Site Request Forgery",
     "desc": "An action performed because the victim's browser sent their cookies.",
     "re": re.compile(r"cross[- ]site request forgery|\bcsrf\b|\bxsrf\b", re.I)},
    {"id": "SSRF", "name": "Server-Side Request Forgery",
     "desc": "The server is made to fetch an internal or unexpected address.",
     "re": re.compile(r"server[- ]side request forgery|\bssrf\b|dns rebinding", re.I)},
    {"id": "SQLI", "name": "SQL Injection",
     "desc": "User input reaching a SQL query unchanged.",
     "re": re.compile(r"sql injection|\bsqli\b|nosql injection|orm leak", re.I)},
    {"id": "IDOR", "name": "Insecure Direct Object Reference",
     "desc": "An object id in a request is changed to another user's object.",
     "re": re.compile(r"insecure direct object|\bidor\b|direct object reference|mass assignment", re.I)},
    {"id": "RCE", "name": "Code Execution",
     "desc": "Command, code, template, deserialization or upload paths to execution.",
     "re": re.compile(r"code injection|command injection|os command|remote code|deserialization|template injection|remote file inclusion|unrestricted upload|malware|dangerous (method|function)|java rmi|server side include|xslt", re.I)},
    {"id": "TRAV", "name": "Path Traversal",
     "desc": "Reading or writing files outside the intended directory.",
     "re": re.compile(r"path traversal|file inclusion|directory traversal|link following|file name or path|search path|resource in another sphere|zip slip", re.I)},
    {"id": "AUTH", "name": "Authentication",
     "desc": "Login, session, credential and brute-force weaknesses.",
     "re": re.compile(r"authentication|brute force|session fixation|password|credential|session expiration|2fa|two[- ]factor|reliance on cookies", re.I)},
    {"id": "ACL", "name": "Access Control",
     "desc": "Authorisation, privilege, permission and forced-browsing gaps.",
     "re": re.compile(r"access control|authorization|authorisation|privilege|permission|forced browsing|client[- ]side enforcement|security decision|export of android", re.I)},
    {"id": "INFO", "name": "Information Disclosure",
     "desc": "Sensitive data exposed: files, errors, internal state, PII.",
     "re": re.compile(r"information disclosure|information exposure|cleartext|sensitive|exposure|privacy|plaintext|debug code|pii", re.I)},
    {"id": "REDIR", "name": "Open Redirect",
     "desc": "A redirect or return URL that is not validated.",
     "re": re.compile(r"open redirect|url redirection|unvalidated redirect", re.I)},
    {"id": "LOGIC", "name": "Business Logic",
     "desc": "Race conditions, TOCTOU, price/coupon and expected-behaviour flaws.",
     "re": re.compile(r"business logic|race condition|time[- ]of[- ]check|toctou|assumed[- ]immutable|expected behavior|incorrect comparison|critical state data|partial string comparison", re.I)},
    {"id": "MEM", "name": "Memory Corruption",
     "desc": "Buffer, overflow, use-after-free, type confusion and format strings.",
     "re": re.compile(r"buffer|overflow|underflow|out[- ]of[- ]bounds|use after free|use[- ]after[- ]free|double free|null pointer|null termination|uninitialized|type confusion|off[- ]by[- ]one|format string|write[- ]what[- ]where|integer overflow", re.I)},
    {"id": "DOS", "name": "Denial of Service",
     "desc": "Resource consumption, recursion, entity expansion, throttling.",
     "re": re.compile(r"denial of service|resource consumption|uncontrolled recursion|resource exhaustion|allocation of resources|throttling|entity expansion|unreachable exit|\bddos\b", re.I)},
    {"id": "INJ", "name": "Injection and Smuggling",
     "desc": "Header, CRLF, XXE, LDAP, XPath, GraphQL and HTTP smuggling.",
     "re": re.compile(r"injection|crlf|smuggling|response splitting|xml external|\bxxe\b|input validation|neutralization|url encoding|csv file|ldap|xpath|graphql|parameter pollution", re.I)},
    {"id": "CRYPTO", "name": "Cryptography",
     "desc": "Certificates, weak ciphers, randomness, hashing, MITM.",
     "re": re.compile(r"cryptograph|certificate|weak|random|\bssl\b|\btls\b|man[- ]in[- ]the[- ]middle|hash|encryption|data authenticity|reverse dns", re.I)},
    {"id": "CONF", "name": "Misconfiguration",
     "desc": "CORS, clickjacking, subdomain takeover, headers, caching, logging.",
     "re": re.compile(r"misconfiguration|secure design|ui redress|clickjacking|phishing|spoofing|subdomain takeover|\bcors\b|origin|logging|obscurity|known vulnerabilities|temporary file|cache poisoning|misrepresentation|exceptional conditions|extraneous untrusted", re.I)},
]
OTHER = {"id": "OTHER", "name": "Other weaknesses",
         "desc": "Reports whose weakness fits no class above.", "re": re.compile(r".*")}

ALL = CLASSES + [OTHER]


def class_of(text: str | None) -> dict:
    """The class a HackerOne weakness name (or guessed weakness) belongs to."""
    if not text:
        return OTHER
    for c in CLASSES:
        if c["re"].search(text):
            return c
    return OTHER


def classes_for_title(title: str) -> list[dict]:
    """Classes mentioned in a title, for pages that cross-reference."""
    return [c for c in CLASSES if c["re"].search(title)]


# The closest standard HackerOne weakness name, judged from a title. Used when
# the program filed the report without a weakness.
TITLE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(stored|persistent).{0,20}(xss|cross.?site scripting)|(xss|cross.?site scripting).{0,20}(stored|persistent)", re.I), "Cross-site Scripting (XSS) - Stored"),
    (re.compile(r"reflected.{0,20}(xss|cross.?site scripting)|(xss|cross.?site scripting).{0,20}reflected", re.I), "Cross-site Scripting (XSS) - Reflected"),
    (re.compile(r"dom.{0,12}(xss|cross.?site scripting)", re.I), "Cross-site Scripting (XSS) - DOM"),
    (re.compile(r"\bxss\b|cross.?site scripting|html injection|script injection", re.I), "Cross-site Scripting (XSS) - Generic"),
    (re.compile(r"\bcsrf\b|\bxsrf\b|cross.?site request forgery", re.I), "Cross-Site Request Forgery (CSRF)"),
    (re.compile(r"\bssrf\b|server.?side request forgery", re.I), "Server-Side Request Forgery (SSRF)"),
    (re.compile(r"sql injection|\bsqli\b", re.I), "SQL Injection"),
    (re.compile(r"\bidor\b|insecure direct object", re.I), "Insecure Direct Object Reference (IDOR)"),
    (re.compile(r"open redirect|unvalidated redirect|url redirect|redirection", re.I), "Open Redirect"),
    (re.compile(r"request smuggling", re.I), "HTTP Request Smuggling"),
    (re.compile(r"\bcrlf\b|header injection|response splitting", re.I), "CRLF Injection"),
    (re.compile(r"\bxxe\b|xml external", re.I), "XML External Entities (XXE)"),
    (re.compile(r"\brce\b|remote code execution|code execution|command injection|command execution|arbitrary code", re.I), "Code Injection"),
    (re.compile(r"path traversal|directory traversal|\blfi\b|local file|arbitrary file (read|access)", re.I), "Path Traversal"),
    (re.compile(r"click.?jacking|x-frame-options|ui redress", re.I), "UI Redressing (Clickjacking)"),
    (re.compile(r"brute.?force|rate.?limit|captcha|lockout", re.I), "Improper Restriction of Authentication Attempts"),
    (re.compile(r"privilege escalation|escalat", re.I), "Privilege Escalation"),
    (re.compile(r"2fa|two.?factor|password|log.?in|sign.?in|authenticat|session|oauth|account takeover|token", re.I), "Improper Authentication - Generic"),
    (re.compile(r"access control|unauthori[sz]ed|permission|authorization|without (permission|being)|restricted|private|can (view|read|see|delete|edit|modify|access)|bypass", re.I), "Improper Access Control - Generic"),
    (re.compile(r"subdomain takeover|\bspf\b|dmarc|\bdns\b|misconfig|\bcors\b|missing .{0,30}(header|flag)|security headers?|hsts|cookie", re.I), "Misconfiguration"),
    (re.compile(r"ssl|tls|certificate|crypto|cipher|heartbleed|poodle|\bmitm\b", re.I), "Cryptographic Issues - Generic"),
    (re.compile(r"overflow|out.of.bounds|use.after.free|memory corruption|heap|segfault|double free|null pointer|\boob\b", re.I), "Memory Corruption - Generic"),
    (re.compile(r"denial of service|\bdos\b|\bddos\b|crash|resource exhaustion|infinite loop|hang", re.I), "Uncontrolled Resource Consumption"),
    (re.compile(r"race condition|business logic|logic (flaw|error|bug)|payment|price|coupon|free |unlimited", re.I), "Business Logic Errors"),
    (re.compile(r"disclos|leak|expos|sensitive|information|enumerat|visible|reveal", re.I), "Information Disclosure"),
    (re.compile(r"spoof|phishing|homograph|tabnabbing|content injection|text injection", re.I), "Violation of Secure Design Principles"),
    (re.compile(r"injection", re.I), "Code Injection"),
]


def guess_weakness(title: str) -> str:
    for rx, name in TITLE_RULES:
        if rx.search(title):
            return name
    return ""


_SEV = [
    (re.compile(r"\b(rce|remote code execution|command injection|os command|deserialization|sql injection|\bssrf\b|xxe)\b", re.I), "critical"),
    (re.compile(r"\b(xss|cross-site scripting|csrf|ssrf|idor|authentication bypass|account takeover|privilege escalation|path traversal|file inclusion)\b", re.I), "high"),
    (re.compile(r"\b(open redirect|cors|clickjacking|information disclosure|information leak|misconfig|rate limit|2fa)\b", re.I), "medium"),
    (re.compile(r"\b(denial of service|\bdos\b)\b", re.I), "medium"),
]


def guess_severity(title: str) -> str | None:
    for rx, sev in _SEV:
        if rx.search(title):
            return sev
    return None
