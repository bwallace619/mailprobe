#!/usr/bin/env python3

"""
MailProbe
=========
A single-file, explainable email validation engine.

Dependencies:
    pip install dnspython

Examples:
    python mailprobe.py test@gmail.com
    python mailprobe.py test@gmail.com --mode fast
    python mailprobe.py test@gmail.com --mode deep --pretty

Important:
SMTP mailbox verification is not definitive.
Many providers intentionally hide mailbox existence.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import smtplib
import socket
import ssl
import string
import sys
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Optional

try:
    import dns.exception
    import dns.resolver
except ImportError:
    print(
        "Missing dependency: dnspython\n"
        "Install it with:\n\n"
        "    pip install dnspython\n",
        file=sys.stderr,
    )
    sys.exit(1)

VERSION = "1.0.0"
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 253
DEFAULT_DNS_TIMEOUT = 4.0
DEFAULT_SMTP_TIMEOUT = 8.0

COMMON_DOMAINS = [
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "me.com", "mac.com", "yahoo.com", "yahoo.co.uk",
    "proton.me", "protonmail.com", "fastmail.com", "aol.com", "zoho.com",
    "gmx.com", "gmx.co.uk", "mail.com",
]

ROLE_PREFIXES = {
    "admin", "administrator", "billing", "contact", "hello", "help", "info",
    "inquiries", "jobs", "mail", "marketing", "newsletter", "noreply",
    "no-reply", "office", "postmaster", "privacy", "sales", "security",
    "support", "team", "webmaster", "abuse", "accounts", "finance", "hr",
    "legal", "press",
}

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "guerrillamail.com",
    "guerrillamail.net", "guerrillamail.org", "mailinator.com", "maildrop.cc",
    "temp-mail.org", "tempmail.com", "throwawaymail.com", "yopmail.com",
    "yopmail.fr", "sharklasers.com", "grr.la", "dispostable.com",
    "getnada.com", "trashmail.com", "fakeinbox.com", "mintemail.com",
}

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "me.com", "yahoo.com", "yahoo.co.uk", "protonmail.com",
    "proton.me", "aol.com", "gmx.com", "gmx.co.uk", "mail.com", "zoho.com",
}

PROVIDER_PATTERNS = {
    "Google Workspace / Gmail": ["google.com", "googlemail.com", "aspmx.l.google.com"],
    "Microsoft 365 / Outlook": ["outlook.com", "protection.outlook.com"],
    "Proton Mail": ["protonmail.ch", "protonmail.com"],
    "Fastmail": ["messagingengine.com"],
    "Zoho Mail": ["zoho.com", "zohomail.com"],
    "Yahoo": ["yahoodns.net", "yahoo.com"],
    "Apple iCloud": ["icloud.com"],
}

CONFUSABLE_CHARS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u04cf": "l", "\u03b1": "a", "\u03bf": "o", "\u03c1": "p",
    "\u03c7": "x", "\u03bd": "v", "\uff4c": "l", "\u217c": "l",
}


@dataclass
class Check:
    name: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class ValidationResult:
    input: str
    normalized: Optional[str]
    local_part: Optional[str]
    domain: Optional[str]
    ascii_domain: Optional[str]
    mode: str
    verdict: str = "unknown"
    confidence: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def timed_check(name: str, func, *args, **kwargs) -> Check:
    start = time.perf_counter()
    try:
        status, details = func(*args, **kwargs)
    except Exception as exc:
        status = "error"
        details = {"error": type(exc).__name__, "message": str(exc)}
    return Check(name, status, details, round((time.perf_counter() - start) * 1000, 2))


def normalize_email(email: str) -> str:
    email = email.strip()
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    domain = unicodedata.normalize("NFC", domain).lower().strip()
    local = unicodedata.normalize("NFC", local).strip()
    return f"{local}@{domain}"


def domain_to_ascii(domain: str) -> Optional[str]:
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def random_mailbox(prefix: str = "mailprobe") -> str:
    alphabet = string.ascii_lowercase + string.digits
    return f"{prefix}-" + "".join(secrets.choice(alphabet) for _ in range(20))


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a):
        current = [i + 1]
        for j, char_b in enumerate(b):
            current.append(min(previous[j + 1] + 1, current[j] + 1, previous[j] + (char_a != char_b)))
        previous = current
    return previous[-1]


def find_domain_suggestion(domain: str) -> Optional[dict[str, Any]]:
    domain = domain.lower()
    if domain in COMMON_DOMAINS:
        return None
    best_domain, best_score, best_distance = None, 0.0, 999
    for candidate in COMMON_DOMAINS:
        distance = levenshtein(domain, candidate)
        ratio = SequenceMatcher(None, domain, candidate).ratio()
        if distance < best_distance or (distance == best_distance and ratio > best_score):
            best_domain, best_score, best_distance = candidate, ratio, distance
    if best_domain and best_distance <= 2 and best_score >= 0.70:
        return {"suggestion": best_domain, "distance": best_distance, "similarity": round(best_score, 3)}
    return None


def detect_scripts(value: str) -> set[str]:
    scripts = set()
    for char in value:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            scripts.add("Latin")
        elif "CYRILLIC" in name:
            scripts.add("Cyrillic")
        elif "GREEK" in name:
            scripts.add("Greek")
        elif "HEBREW" in name:
            scripts.add("Hebrew")
        elif "ARABIC" in name:
            scripts.add("Arabic")
        elif "HANGUL" in name:
            scripts.add("Hangul")
        elif "CJK" in name or "IDEOGRAPH" in name:
            scripts.add("CJK")
        else:
            scripts.add("Other")
    return scripts


LOCAL_UNQUOTED_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def check_syntax(email: str):
    problems = []
    if not email:
        return "fail", {"problems": ["Email is empty"]}
    if len(email) > MAX_EMAIL_LENGTH:
        problems.append("Email exceeds maximum recommended length")
    if email.count("@") != 1:
        return "fail", {"problems": problems + ["Email must contain exactly one @ character"]}
    local, domain = email.rsplit("@", 1)
    if not local:
        problems.append("Local part is empty")
    if not domain:
        problems.append("Domain is empty")
    if len(local) > MAX_LOCAL_LENGTH:
        problems.append("Local part exceeds 64 characters")
    if len(domain) > MAX_DOMAIN_LENGTH:
        problems.append("Domain exceeds 253 characters")
    if local.startswith("."):
        problems.append("Local part begins with a dot")
    if local.endswith("."):
        problems.append("Local part ends with a dot")
    if ".." in local:
        problems.append("Local part contains consecutive dots")
    quoted_local = len(local) >= 2 and local.startswith('"') and local.endswith('"')
    if not quoted_local and not LOCAL_UNQUOTED_RE.match(local):
        problems.append("Local part contains unsupported or invalid characters")
    ascii_domain = domain_to_ascii(domain)
    if ascii_domain is None:
        problems.append("Domain cannot be converted to IDNA/Punycode")
    else:
        labels = ascii_domain.split(".")
        if len(labels) < 2:
            problems.append("Domain has no public-looking suffix")
        for label in labels:
            if not label:
                problems.append("Domain contains an empty label")
                continue
            if len(label) > 63:
                problems.append(f"Domain label '{label}' exceeds 63 characters")
            if not DOMAIN_LABEL_RE.match(label):
                problems.append(f"Invalid domain label: {label}")
    return ("fail", {"problems": problems, "quoted_local_part": quoted_local}) if problems else (
        "pass", {"quoted_local_part": quoted_local, "local_length": len(local), "domain_length": len(domain), "total_length": len(email)}
    )


def check_unicode_security(email: str):
    _, domain = email.rsplit("@", 1)
    scripts = detect_scripts(domain)
    confusables = [
        {"character": char, "looks_like": CONFUSABLE_CHARS[char], "unicode_name": unicodedata.name(char, "UNKNOWN")}
        for char in domain if char in CONFUSABLE_CHARS
    ]
    invisible = []
    for char in email:
        if unicodedata.category(char) in {"Cf", "Cc"}:
            invisible.append({"character": repr(char), "unicode": f"U+{ord(char):04X}", "name": unicodedata.name(char, "UNKNOWN")})
    mixed_scripts = len(scripts) > 1
    dangerous = bool(confusables or invisible or mixed_scripts)
    return ("warning" if dangerous else "pass"), {
        "scripts": sorted(scripts), "mixed_scripts": mixed_scripts,
        "confusable_characters": confusables,
        "invisible_or_control_characters": invisible,
        "risk": "elevated" if dangerous else "low",
    }


def check_role_account(local: str):
    local_clean = local.lower().split("+", 1)[0]
    is_role = local_clean in ROLE_PREFIXES
    return ("warning" if is_role else "pass"), {"role_account": is_role, "prefix": local_clean}


def check_disposable(domain: str):
    disposable = domain.lower() in DISPOSABLE_DOMAINS
    return ("warning" if disposable else "pass"), {"disposable": disposable, "confidence": 1.0 if disposable else 0.0}


def check_free_provider(domain: str):
    return "pass", {"free_provider": domain.lower() in FREE_PROVIDERS}


def check_typo(domain: str):
    suggestion = find_domain_suggestion(domain)
    return ("warning", suggestion) if suggestion else ("pass", {"suggestion": None})


def create_resolver(timeout: float = DEFAULT_DNS_TIMEOUT):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_records(domain: str, record_type: str, timeout: float = DEFAULT_DNS_TIMEOUT):
    resolver = create_resolver(timeout)
    try:
        answer = resolver.resolve(domain, record_type)
        return [str(record).rstrip(".") for record in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise TimeoutError(f"DNS lookup timed out for {record_type}")


def check_domain_exists(domain: str, timeout: float):
    resolver = create_resolver(timeout)
    for rtype in ("A", "AAAA", "MX"):
        try:
            resolver.resolve(domain, rtype)
            return "pass", {"exists": True, "resolved_via": rtype}
        except dns.resolver.NXDOMAIN:
            return "fail", {"exists": False, "reason": "NXDOMAIN"}
        except Exception:
            pass
    return "unknown", {"exists": None, "reason": "No usable DNS response"}


def get_mx_records(domain: str, timeout: float):
    resolver = create_resolver(timeout)
    try:
        answer = resolver.resolve(domain, "MX")
        records = sorted(
            [{"priority": int(r.preference), "host": str(r.exchange).rstrip(".").lower()} for r in answer],
            key=lambda item: item["priority"],
        )
        null_mx = len(records) == 1 and records[0]["host"] in {"", "."}
        return ("fail" if null_mx else "pass"), {"mx_records": records, "null_mx": null_mx}
    except dns.resolver.NXDOMAIN:
        return "fail", {"mx_records": [], "reason": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        try:
            addresses = resolve_records(domain, "A", timeout)
            if addresses:
                return "warning", {"mx_records": [], "a_record_fallback": True, "addresses": addresses}
        except Exception:
            pass
        return "fail", {"mx_records": [], "reason": "No MX records"}
    except Exception as exc:
        return "unknown", {"mx_records": [], "reason": str(exc)}


def _txt_prefixed(domain: str, prefix: str, timeout: float):
    records = [r.strip('"') for r in resolve_records(domain, "TXT", timeout)]
    found = [r for r in records if r.lower().startswith(prefix.lower())]
    return ("pass" if found else "warning"), {"present": bool(found), "records": found}


def check_spf(domain: str, timeout: float):
    return _txt_prefixed(domain, "v=spf1", timeout)


def check_dmarc(domain: str, timeout: float):
    return _txt_prefixed(f"_dmarc.{domain}", "v=dmarc1", timeout)


def check_mta_sts(domain: str, timeout: float):
    records = [r.strip('"') for r in resolve_records(f"_mta-sts.{domain}", "TXT", timeout)]
    found = [r for r in records if "v=STSv1" in r]
    return ("pass" if found else "neutral"), {"present": bool(found), "records": found}


def check_tls_rpt(domain: str, timeout: float):
    records = [r.strip('"') for r in resolve_records(f"_smtp._tls.{domain}", "TXT", timeout)]
    found = [r for r in records if "v=TLSRPTv1" in r]
    return ("pass" if found else "neutral"), {"present": bool(found), "records": found}


def detect_provider(mx_records: list[dict[str, Any]]):
    mx_hosts = [r["host"].lower() for r in mx_records]
    for provider, patterns in PROVIDER_PATTERNS.items():
        for host in mx_hosts:
            for pattern in patterns:
                if pattern in host:
                    return "pass", {"provider": provider, "matched_mx": host}
    return "neutral", {"provider": "Unknown / self-hosted", "matched_mx": None}


def decode_smtp_message(message):
    return message.decode("utf-8", errors="replace") if isinstance(message, bytes) else str(message)


def smtp_probe(target_email: str, mx_host: str, timeout: float):
    hostname = socket.gethostname() or "mailprobe.local"
    result = {"mx_host": mx_host, "connected": False, "starttls_supported": False, "smtp_code": None, "smtp_message": None}
    smtp = None
    try:
        smtp = smtplib.SMTP(mx_host, 25, timeout=timeout)
        smtp.ehlo(hostname)
        result["connected"] = True
        if smtp.has_extn("STARTTLS"):
            result["starttls_supported"] = True
            try:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo(hostname)
            except Exception as exc:
                result["tls_error"] = str(exc)
        sender = f"probe-{secrets.token_hex(4)}@example.com"
        mail_code, mail_message = smtp.mail(sender)
        result["mail_from"] = {"code": mail_code, "message": decode_smtp_message(mail_message)}
        if mail_code >= 500:
            return "unknown", result
        rcpt_code, rcpt_message = smtp.rcpt(target_email)
        result["smtp_code"] = rcpt_code
        result["smtp_message"] = decode_smtp_message(rcpt_message)
        if rcpt_code in {250, 251, 252}:
            return "pass", result
        if 400 <= rcpt_code <= 499:
            result["temporary_failure"] = True
            return "unknown", result
        if 500 <= rcpt_code <= 599:
            return "fail", result
        return "unknown", result
    except (socket.timeout, TimeoutError, smtplib.SMTPServerDisconnected, ConnectionRefusedError, OSError) as exc:
        result["error"] = str(exc)
        return "unknown", result
    finally:
        if smtp:
            try:
                smtp.quit()
            except Exception:
                pass


def check_smtp(email: str, mx_records: list[dict[str, Any]], timeout: float):
    attempts = []
    for mx in mx_records[:3]:
        status, details = smtp_probe(email, mx["host"], timeout)
        attempts.append(details)
        if status == "pass":
            return "pass", {"mailbox_response": "accepted", "attempts": attempts}
        if status == "fail":
            return "fail", {"mailbox_response": "rejected", "attempts": attempts}
    return "unknown", {"mailbox_response": "unknown", "attempts": attempts}


def check_catch_all(domain: str, mx_records: list[dict[str, Any]], timeout: float):
    if not mx_records:
        return "unknown", {"catch_all": None, "reason": "No MX records"}
    test_results = []
    for _ in range(2):
        email = f"{random_mailbox()}@{domain}"
        status, details = smtp_probe(email, mx_records[0]["host"], timeout)
        test_results.append({"address": email, "status": status, "details": details})
    accepted = [x for x in test_results if x["status"] == "pass"]
    rejected = [x for x in test_results if x["status"] == "fail"]
    if len(accepted) == len(test_results):
        return "warning", {"catch_all": True, "tests": test_results}
    if len(rejected) == len(test_results):
        return "pass", {"catch_all": False, "tests": test_results}
    return "unknown", {"catch_all": None, "tests": test_results}


def calculate_scores(checks: list[Check], mode: str):
    lookup = {c.name: c for c in checks}
    syntax_score = domain_score = mail_server_score = trust_score = 1.0
    mailbox_score = 0.5
    if lookup.get("syntax") and lookup["syntax"].status == "fail": syntax_score = 0.0
    if lookup.get("unicode_security") and lookup["unicode_security"].status == "warning": trust_score -= 0.25
    if lookup.get("domain_typo") and lookup["domain_typo"].status == "warning": trust_score -= 0.15
    if lookup.get("disposable") and lookup["disposable"].details.get("disposable"): trust_score -= 0.45
    if lookup.get("domain_exists"):
        domain_score = 0.0 if lookup["domain_exists"].status == "fail" else 0.5 if lookup["domain_exists"].status == "unknown" else 1.0
    if lookup.get("mx"):
        mail_server_score = {"fail": 0.0, "warning": 0.65, "unknown": 0.5}.get(lookup["mx"].status, 1.0)
    if lookup.get("smtp"):
        mailbox_score = {"pass": 0.95, "fail": 0.0}.get(lookup["smtp"].status, 0.5)
    if lookup.get("catch_all") and lookup["catch_all"].details.get("catch_all") is True:
        mailbox_score = min(mailbox_score, 0.65)
    if lookup.get("spf") and lookup["spf"].status == "warning": trust_score -= 0.05
    if lookup.get("dmarc") and lookup["dmarc"].status == "warning": trust_score -= 0.05
    trust_score = max(0.0, min(1.0, trust_score))
    scores = {
        "syntax": round(syntax_score, 3), "domain": round(domain_score, 3),
        "mail_server": round(mail_server_score, 3), "mailbox": round(mailbox_score, 3),
        "trust": round(trust_score, 3),
    }
    if mode == "fast":
        confidence = syntax_score * 0.5 + trust_score * 0.5
    elif mode == "standard":
        confidence = syntax_score * 0.30 + domain_score * 0.25 + mail_server_score * 0.25 + trust_score * 0.20
    else:
        confidence = syntax_score * 0.20 + domain_score * 0.20 + mail_server_score * 0.20 + mailbox_score * 0.25 + trust_score * 0.15
    return scores, round(max(0.0, min(1.0, confidence)), 3)


def choose_verdict(scores: dict[str, float], checks: list[Check]):
    lookup = {c.name: c for c in checks}
    if scores["syntax"] == 0: return "invalid"
    if scores["domain"] == 0 or scores["mail_server"] == 0: return "undeliverable"
    smtp = lookup.get("smtp")
    if smtp:
        if smtp.status == "fail": return "undeliverable"
        if smtp.status == "pass":
            catch_all = lookup.get("catch_all")
            return "probably_deliverable" if catch_all and catch_all.details.get("catch_all") is True else "deliverable"
        return "unknown"
    overall = (scores["syntax"] + scores["domain"] + scores["mail_server"] + scores["trust"]) / 4
    return "probably_deliverable" if overall >= 0.85 else "unknown" if overall >= 0.55 else "probably_undeliverable"


def validate_email(email: str, mode: str = "standard", dns_timeout: float = DEFAULT_DNS_TIMEOUT, smtp_timeout: float = DEFAULT_SMTP_TIMEOUT) -> ValidationResult:
    mode = mode.lower()
    if mode not in {"fast", "standard", "deep"}:
        raise ValueError("mode must be: fast, standard or deep")
    normalized = normalize_email(email)
    local = domain = ascii_domain = None
    if "@" in normalized:
        local, domain = normalized.rsplit("@", 1)
        ascii_domain = domain_to_ascii(domain)
    result = ValidationResult(email, normalized, local, domain, ascii_domain, mode)
    checks: list[Check] = []
    syntax = timed_check("syntax", check_syntax, normalized)
    checks.append(syntax)
    if syntax.status == "fail":
        result.checks = [asdict(c) for c in checks]
        result.scores = {"syntax": 0.0, "domain": 0.0, "mail_server": 0.0, "mailbox": 0.0, "trust": 0.0}
        result.confidence = 1.0
        result.verdict = "invalid"
        return result
    checks += [
        timed_check("unicode_security", check_unicode_security, normalized),
        timed_check("role_account", check_role_account, local),
        timed_check("disposable", check_disposable, domain),
        timed_check("free_provider", check_free_provider, domain),
    ]
    typo = timed_check("domain_typo", check_typo, domain)
    checks.append(typo)
    if typo.status == "warning" and typo.details.get("suggestion"):
        result.suggestions.append(f"Did you mean {local}@{typo.details['suggestion']}?")
    if mode != "fast":
        domain_target = ascii_domain or domain
        checks.append(timed_check("domain_exists", check_domain_exists, domain_target, dns_timeout))
        mx_check = timed_check("mx", get_mx_records, domain_target, dns_timeout)
        checks.append(mx_check)
        mx_records = mx_check.details.get("mx_records", [])
        checks += [
            timed_check("provider", detect_provider, mx_records),
            timed_check("spf", check_spf, domain_target, dns_timeout),
            timed_check("dmarc", check_dmarc, domain_target, dns_timeout),
            timed_check("mta_sts", check_mta_sts, domain_target, dns_timeout),
            timed_check("tls_rpt", check_tls_rpt, domain_target, dns_timeout),
        ]
        if mode == "deep" and mx_records:
            smtp_check = timed_check("smtp", check_smtp, normalized, mx_records, smtp_timeout)
            checks.append(smtp_check)
            if smtp_check.status in {"pass", "unknown"}:
                checks.append(timed_check("catch_all", check_catch_all, domain_target, mx_records, smtp_timeout))
    for check in checks:
        if check.status == "warning": result.warnings.append(f"{check.name}: warning")
        if check.status == "error": result.warnings.append(f"{check.name}: check failed")
    scores, confidence = calculate_scores(checks, mode)
    result.scores = scores
    result.confidence = confidence
    result.verdict = choose_verdict(scores, checks)
    result.checks = [asdict(c) for c in checks]
    result.metadata = {"validator": "MailProbe", "version": VERSION, "smtp_verification_is_definitive": False}
    return result


def main():
    parser = argparse.ArgumentParser(description="MailProbe - explainable email validation engine")
    parser.add_argument("email", help="Email address to validate")
    parser.add_argument("--mode", choices=["fast", "standard", "deep"], default="standard", help="Validation depth")
    parser.add_argument("--dns-timeout", type=float, default=DEFAULT_DNS_TIMEOUT, help="DNS timeout in seconds")
    parser.add_argument("--smtp-timeout", type=float, default=DEFAULT_SMTP_TIMEOUT, help="SMTP timeout in seconds")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--version", action="version", version=f"MailProbe {VERSION}")
    args = parser.parse_args()
    try:
        result = validate_email(args.email, args.mode, args.dns_timeout, args.smtp_timeout)
        print(json.dumps(asdict(result), indent=2 if args.pretty else None, ensure_ascii=False))
    except KeyboardInterrupt:
        print("\nValidation cancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
