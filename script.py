#!/usr/bin/env python3

"""
MailProbe
=========
A single-file, explainable email validation engine.

Features:
- Email syntax validation
- Email normalization
- IDN / Punycode handling
- Unicode security checks
- Homoglyph / mixed-script detection
- Role-account detection
- Disposable-domain detection
- Common domain typo suggestions
- DNS / MX validation
- SPF detection
- DMARC detection
- MTA-STS detection
- TLS-RPT detection
- Mail provider detection
- SMTP RCPT probing
- Catch-all detection
- Confidence scoring
- FAST / STANDARD / DEEP validation modes
- JSON CLI output

Dependencies:
    pip install dnspython

Examples:
    python mailprobe.py test@gmail.com
    python mailprobe.py test@gmail.com --mode fast
    python mailprobe.py test@gmail.com --mode deep
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

from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from typing import Any, Optional

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print(
        "Missing dependency: dnspython\n"
        "Install it with:\n\n"
        "    pip install dnspython\n",
        file=sys.stderr,
    )
    sys.exit(1)


VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 253

DEFAULT_DNS_TIMEOUT = 4.0
DEFAULT_SMTP_TIMEOUT = 8.0

COMMON_DOMAINS = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "yahoo.com",
    "yahoo.co.uk",
    "proton.me",
    "protonmail.com",
    "fastmail.com",
    "aol.com",
    "zoho.com",
    "gmx.com",
    "gmx.co.uk",
    "mail.com",
]

ROLE_PREFIXES = {
    "admin",
    "administrator",
    "billing",
    "contact",
    "hello",
    "help",
    "info",
    "inquiries",
    "jobs",
    "mail",
    "marketing",
    "newsletter",
    "noreply",
    "no-reply",
    "office",
    "postmaster",
    "privacy",
    "sales",
    "security",
    "support",
    "team",
    "webmaster",
    "abuse",
    "accounts",
    "finance",
    "hr",
    "legal",
    "press",
}

DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "10minutemail.net",
    "guerrillamail.com",
    "guerrillamail.net",
    "guerrillamail.org",
    "mailinator.com",
    "maildrop.cc",
    "temp-mail.org",
    "tempmail.com",
    "throwawaymail.com",
    "yopmail.com",
    "yopmail.fr",
    "sharklasers.com",
    "grr.la",
    "dispostable.com",
    "getnada.com",
    "trashmail.com",
    "fakeinbox.com",
    "mintemail.com",
}

FREE_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "me.com",
    "yahoo.com",
    "yahoo.co.uk",
    "protonmail.com",
    "proton.me",
    "aol.com",
    "gmx.com",
    "gmx.co.uk",
    "mail.com",
    "zoho.com",
}

PROVIDER_PATTERNS = {
    "Google Workspace / Gmail": [
        "google.com",
        "googlemail.com",
        "aspmx.l.google.com",
    ],
    "Microsoft 365 / Outlook": [
        "outlook.com",
        "protection.outlook.com",
    ],
    "Proton Mail": [
        "protonmail.ch",
        "protonmail.com",
    ],
    "Fastmail": [
        "messagingengine.com",
    ],
    "Zoho Mail": [
        "zoho.com",
        "zohomail.com",
    ],
    "Yahoo": [
        "yahoodns.net",
        "yahoo.com",
    ],
    "Apple iCloud": [
        "icloud.com",
    ],
}

CONFUSABLE_CHARS = {
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u04cf": "l",
    "\u03b1": "a",  # Greek alpha
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c7": "x",
    "\u03bd": "v",
    "\uff4c": "l",
    "\u217c": "l",
}


# ---------------------------------------------------------------------------
# DATA TYPES
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def timed_check(name: str, func, *args, **kwargs) -> Check:
    start = time.perf_counter()

    try:
        status, details = func(*args, **kwargs)
    except Exception as exc:
        status = "error"
        details = {
            "error": type(exc).__name__,
            "message": str(exc),
        }

    duration = (time.perf_counter() - start) * 1000

    return Check(
        name=name,
        status=status,
        details=details,
        duration_ms=round(duration, 2),
    )


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
    random_part = "".join(
        secrets.choice(string.ascii_lowercase + string.digits)
        for _ in range(20)
    )

    return f"{prefix}-{random_part}"


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a

    if len(b) == 0:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a):
        current = [i + 1]

        for j, char_b in enumerate(b):
            insert = previous[j + 1] + 1
            delete = current[j] + 1
            substitute = previous[j] + (char_a != char_b)

            current.append(min(insert, delete, substitute))

        previous = current

    return previous[-1]


def find_domain_suggestion(domain: str) -> Optional[dict[str, Any]]:
    domain = domain.lower()

    if domain in COMMON_DOMAINS:
        return None

    best_domain = None
    best_score = 0.0
    best_distance = 999

    for candidate in COMMON_DOMAINS:
        distance = levenshtein(domain, candidate)
        ratio = SequenceMatcher(None, domain, candidate).ratio()

        if distance < best_distance or (
            distance == best_distance and ratio > best_score
        ):
            best_domain = candidate
            best_score = ratio
            best_distance = distance

    if best_domain is None:
        return None

    if best_distance <= 2 and best_score >= 0.70:
        return {
            "suggestion": best_domain,
            "distance": best_distance,
            "similarity": round(best_score, 3),
        }

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


# ---------------------------------------------------------------------------
# SYNTAX
# ---------------------------------------------------------------------------

LOCAL_UNQUOTED_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$"
)

DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def check_syntax(email: str):
    problems = []

    if not email:
        return "fail", {"problems": ["Email is empty"]}

    if len(email) > MAX_EMAIL_LENGTH:
        problems.append("Email exceeds maximum recommended length")

    if email.count("@") != 1:
        problems.append("Email must contain exactly one @ character")

        return "fail", {"problems": problems}

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

    quoted_local = (
        len(local) >= 2
        and local.startswith('"')
        and local.endswith('"')
    )

    if not quoted_local and not LOCAL_UNQUOTED_RE.match(local):
        problems.append(
            "Local part contains unsupported or invalid characters"
        )

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
                problems.append(
                    f"Domain label '{label}' exceeds 63 characters"
                )

            if not DOMAIN_LABEL_RE.match(label):
                problems.append(
                    f"Invalid domain label: {label}"
                )

    if problems:
        return "fail", {
            "problems": problems,
            "quoted_local_part": quoted_local,
        }

    return "pass", {
        "quoted_local_part": quoted_local,
        "local_length": len(local),
        "domain_length": len(domain),
        "total_length": len(email),
    }


# ---------------------------------------------------------------------------
# UNICODE / SECURITY
# ---------------------------------------------------------------------------

def check_unicode_security(email: str):
    local, domain = email.rsplit("@", 1)

    scripts = detect_scripts(domain)

    confusables = []

    for char in domain:
        if char in CONFUSABLE_CHARS:
            confusables.append(
                {
                    "character": char,
                    "looks_like": CONFUSABLE_CHARS[char],
                    "unicode_name": unicodedata.name(char, "UNKNOWN"),
                }
            )

    invisible = []

    for char in email:
        category = unicodedata.category(char)

        if category in {"Cf", "Cc"}:
            invisible.append(
                {
                    "character": repr(char),
                    "unicode": f"U+{ord(char):04X}",
                    "name": unicodedata.name(char, "UNKNOWN"),
                }
            )

    mixed_scripts = len(scripts) > 1

    dangerous = bool(
        confusables
        or invisible
        or mixed_scripts
    )

    return (
        "warning" if dangerous else "pass",
        {
            "scripts": sorted(scripts),
            "mixed_scripts": mixed_scripts,
            "confusable_characters": confusables,
            "invisible_or_control_characters": invisible,
            "risk": "elevated" if dangerous else "low",
        },
    )


# ---------------------------------------------------------------------------
# ADDRESS CLASSIFICATION
# ---------------------------------------------------------------------------

def check_role_account(local: str):
    local_clean = local.lower().split("+", 1)[0]

    is_role = local_clean in ROLE_PREFIXES

    return (
        "warning" if is_role else "pass",
        {
            "role_account": is_role,
            "prefix": local_clean,
        },
    )


def check_disposable(domain: str):
    domain = domain.lower()

    disposable = domain in DISPOSABLE_DOMAINS

    return (
        "warning" if disposable else "pass",
        {
            "disposable": disposable,
            "confidence": 1.0 if disposable else 0.0,
        },
    )


def check_free_provider(domain: str):
    free = domain.lower() in FREE_PROVIDERS

    return "pass", {
        "free_provider": free,
    }


def check_typo(domain: str):
    suggestion = find_domain_suggestion(domain)

    if not suggestion:
        return "pass", {
            "suggestion": None,
        }

    return "warning", suggestion


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def create_resolver(timeout: float = DEFAULT_DNS_TIMEOUT):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    return resolver


def resolve_records(
    domain: str,
    record_type: str,
    timeout: float = DEFAULT_DNS_TIMEOUT,
):
    resolver = create_resolver(timeout)

    try:
        answer = resolver.resolve(domain, record_type)

        return [str(record).rstrip(".") for record in answer]

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NoNameservers:
        return []

    except dns.exception.Timeout:
        raise TimeoutError(
            f"DNS lookup timed out for {record_type}"
        )


def check_domain_exists(domain: str, timeout: float):
    resolver = create_resolver(timeout)

    try:
        resolver.resolve(domain, "A")

        return "pass", {
            "exists": True,
            "resolved_via": "A",
        }

    except Exception:
        pass

    try:
        resolver.resolve(domain, "AAAA")

        return "pass", {
            "exists": True,
            "resolved_via": "AAAA",
        }

    except Exception:
        pass

    try:
        resolver.resolve(domain, "MX")

        return "pass", {
            "exists": True,
            "resolved_via": "MX",
        }

    except dns.resolver.NXDOMAIN:
        return "fail", {
            "exists": False,
            "reason": "NXDOMAIN",
        }

    except Exception as exc:
        return "unknown", {
            "exists": None,
            "reason": str(exc),
        }


def get_mx_records(domain: str, timeout: float):
    resolver = create_resolver(timeout)

    try:
        answer = resolver.resolve(domain, "MX")

        records = []

        for record in answer:
            records.append(
                {
                    "priority": int(record.preference),
                    "host": str(record.exchange).rstrip(".").lower(),
                }
            )

        records.sort(key=lambda item: item["priority"])

        null_mx = (
            len(records) == 1
            and records[0]["host"] in {"", "."}
        )

        if null_mx:
            return "fail", {
                "mx_records": records,
                "null_mx": True,
            }

        return "pass", {
            "mx_records": records,
            "null_mx": False,
        }

    except dns.resolver.NXDOMAIN:
        return "fail", {
            "mx_records": [],
            "reason": "NXDOMAIN",
        }

    except dns.resolver.NoAnswer:
        # SMTP permits A-record fallback in some cases.
        try:
            addresses = resolve_records(domain, "A", timeout)

            if addresses:
                return "warning", {
                    "mx_records": [],
                    "a_record_fallback": True,
                    "addresses": addresses,
                }

        except Exception:
            pass

        return "fail", {
            "mx_records": [],
            "reason": "No MX records",
        }

    except Exception as exc:
        return "unknown", {
            "mx_records": [],
            "reason": str(exc),
        }


def check_spf(domain: str, timeout: float):
    records = resolve_records(domain, "TXT", timeout)

    spf_records = []

    for record in records:
        cleaned = record.strip('"')

        if cleaned.lower().startswith("v=spf1"):
            spf_records.append(cleaned)

    return (
        "pass" if spf_records else "warning",
        {
            "present": bool(spf_records),
            "records": spf_records,
        },
    )


def check_dmarc(domain: str, timeout: float):
    name = f"_dmarc.{domain}"

    records = resolve_records(name, "TXT", timeout)

    dmarc_records = []

    for record in records:
        cleaned = record.strip('"')

        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_records.append(cleaned)

    return (
        "pass" if dmarc_records else "warning",
        {
            "present": bool(dmarc_records),
            "records": dmarc_records,
        },
    )


def check_mta_sts(domain: str, timeout: float):
    name = f"_mta-sts.{domain}"

    records = resolve_records(name, "TXT", timeout)

    found = [
        record.strip('"')
        for record in records
        if "v=STSv1" in record
    ]

    return (
        "pass" if found else "neutral",
        {
            "present": bool(found),
            "records": found,
        },
    )


def check_tls_rpt(domain: str, timeout: float):
    name = f"_smtp._tls.{domain}"

    records = resolve_records(name, "TXT", timeout)

    found = [
        record.strip('"')
        for record in records
        if "v=TLSRPTv1" in record
    ]

    return (
        "pass" if found else "neutral",
        {
            "present": bool(found),
            "records": found,
        },
    )


# ---------------------------------------------------------------------------
# PROVIDER DETECTION
# ---------------------------------------------------------------------------

def detect_provider(mx_records: list[dict[str, Any]]):
    mx_hosts = [
        record["host"].lower()
        for record in mx_records
    ]

    for provider, patterns in PROVIDER_PATTERNS.items():
        for host in mx_hosts:
            for pattern in patterns:
                if pattern in host:
                    return "pass", {
                        "provider": provider,
                        "matched_mx": host,
                    }

    return "neutral", {
        "provider": "Unknown / self-hosted",
        "matched_mx": None,
    }


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def smtp_probe(
    target_email: str,
    mx_host: str,
    timeout: float,
):
    hostname = socket.gethostname() or "mailprobe.local"

    result = {
        "mx_host": mx_host,
        "connected": False,
        "starttls_supported": False,
        "smtp_code": None,
        "smtp_message": None,
    }

    smtp = None

    try:
        smtp = smtplib.SMTP(
            mx_host,
            25,
            timeout=timeout,
        )

        smtp.ehlo(hostname)
        result["connected"] = True

        if smtp.has_extn("STARTTLS"):
            result["starttls_supported"] = True

            try:
                context = ssl.create_default_context()

                smtp.starttls(context=context)
                smtp.ehlo(hostname)

            except Exception as exc:
                result["tls_error"] = str(exc)

        # Neutral sender domain deliberately avoids pretending to be
        # the target's own domain.
        sender = f"probe-{secrets.token_hex(4)}@example.com"

        mail_code, mail_message = smtp.mail(sender)

        result["mail_from"] = {
            "code": mail_code,
            "message": decode_smtp_message(mail_message),
        }

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

    except (
        socket.timeout,
        TimeoutError,
        smtplib.SMTPServerDisconnected,
    ) as exc:
        result["error"] = str(exc)

        return "unknown", result

    except ConnectionRefusedError as exc:
        result["error"] = str(exc)

        return "unknown", result

    except OSError as exc:
        result["error"] = str(exc)

        return "unknown", result

    finally:
        if smtp:
            try:
                smtp.quit()
            except Exception:
                pass


def decode_smtp_message(message):
    if isinstance(message, bytes):
        return message.decode(
            "utf-8",
            errors="replace",
        )

    return str(message)


def check_smtp(
    email: str,
    mx_records: list[dict[str, Any]],
    timeout: float,
):
    attempts = []

    for mx in mx_records[:3]:
        status, details = smtp_probe(
            email,
            mx["host"],
            timeout,
        )

        attempts.append(details)

        if status == "pass":
            return "pass", {
                "mailbox_response": "accepted",
                "attempts": attempts,
            }

        if status == "fail":
            return "fail", {
                "mailbox_response": "rejected",
                "attempts": attempts,
            }

    return "unknown", {
        "mailbox_response": "unknown",
        "attempts": attempts,
    }


def check_catch_all(
    domain: str,
    mx_records: list[dict[str, Any]],
    timeout: float,
):
    if not mx_records:
        return "unknown", {
            "catch_all": None,
            "reason": "No MX records",
        }

    test_results = []

    # Two random addresses reduce false positives slightly.
    for _ in range(2):
        mailbox = random_mailbox()
        email = f"{mailbox}@{domain}"

        status, details = smtp_probe(
            email,
            mx_records[0]["host"],
            timeout,
        )

        test_results.append(
            {
                "address": email,
                "status": status,
                "details": details,
            }
        )

    accepted = [
        test
        for test in test_results
        if test["status"] == "pass"
    ]

    rejected = [
        test
        for test in test_results
        if test["status"] == "fail"
    ]

    if len(accepted) == len(test_results):
        return "warning", {
            "catch_all": True,
            "tests": test_results,
        }

    if len(rejected) == len(test_results):
        return "pass", {
            "catch_all": False,
            "tests": test_results,
        }

    return "unknown", {
        "catch_all": None,
        "tests": test_results,
    }


# ---------------------------------------------------------------------------
# SCORING
# ---------------------------------------------------------------------------

def calculate_scores(
    checks: list[Check],
    mode: str,
):
    lookup = {
        check.name: check
        for check in checks
    }

    syntax_score = 1.0
    domain_score = 1.0
    mail_server_score = 1.0
    mailbox_score = 0.5
    trust_score = 1.0

    syntax = lookup.get("syntax")

    if syntax and syntax.status == "fail":
        syntax_score = 0.0

    security = lookup.get("unicode_security")

    if security and security.status == "warning":
        trust_score -= 0.25

    typo = lookup.get("domain_typo")

    if typo and typo.status == "warning":
        trust_score -= 0.15

    disposable = lookup.get("disposable")

    if disposable and disposable.details.get("disposable"):
        trust_score -= 0.45

    domain_exists = lookup.get("domain_exists")

    if domain_exists:
        if domain_exists.status == "fail":
            domain_score = 0.0
        elif domain_exists.status == "unknown":
            domain_score = 0.5

    mx = lookup.get("mx")

    if mx:
        if mx.status == "fail":
            mail_server_score = 0.0
        elif mx.status == "warning":
            mail_server_score = 0.65
        elif mx.status == "unknown":
            mail_server_score = 0.5

    smtp = lookup.get("smtp")

    if smtp:
        if smtp.status == "pass":
            mailbox_score = 0.95
        elif smtp.status == "fail":
            mailbox_score = 0.0
        else:
            mailbox_score = 0.5

    catch_all = lookup.get("catch_all")

    if catch_all:
        if catch_all.details.get("catch_all") is True:
            mailbox_score = min(
                mailbox_score,
                0.65,
            )

    spf = lookup.get("spf")
    dmarc = lookup.get("dmarc")

    if spf and spf.status == "warning":
        trust_score -= 0.05

    if dmarc and dmarc.status == "warning":
        trust_score -= 0.05

    trust_score = max(0.0, min(1.0, trust_score))

    scores = {
        "syntax": round(syntax_score, 3),
        "domain": round(domain_score, 3),
        "mail_server": round(mail_server_score, 3),
        "mailbox": round(mailbox_score, 3),
        "trust": round(trust_score, 3),
    }

    if mode == "fast":
        confidence = (
            syntax_score * 0.5
            + trust_score * 0.5
        )

    elif mode == "standard":
        confidence = (
            syntax_score * 0.30
            + domain_score * 0.25
            + mail_server_score * 0.25
            + trust_score * 0.20
        )

    else:
        confidence = (
            syntax_score * 0.20
            + domain_score * 0.20
            + mail_server_score * 0.20
            + mailbox_score * 0.25
            + trust_score * 0.15
        )

    confidence = max(
        0.0,
        min(1.0, confidence),
    )

    return scores, round(confidence, 3)


def choose_verdict(
    scores: dict[str, float],
    checks: list[Check],
):
    lookup = {
        check.name: check
        for check in checks
    }

    if scores["syntax"] == 0:
        return "invalid"

    if scores["domain"] == 0:
        return "undeliverable"

    if scores["mail_server"] == 0:
        return "undeliverable"

    smtp = lookup.get("smtp")

    if smtp:
        if smtp.status == "fail":
            return "undeliverable"

        if smtp.status == "pass":
            catch_all = lookup.get("catch_all")

            if (
                catch_all
                and catch_all.details.get("catch_all") is True
            ):
                return "probably_deliverable"

            return "deliverable"

        return "unknown"

    overall = (
        scores["syntax"]
        + scores["domain"]
        + scores["mail_server"]
        + scores["trust"]
    ) / 4

    if overall >= 0.85:
        return "probably_deliverable"

    if overall >= 0.55:
        return "unknown"

    return "probably_undeliverable"


# ---------------------------------------------------------------------------
# VALIDATOR
# ---------------------------------------------------------------------------

def validate_email(
    email: str,
    mode: str = "standard",
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    smtp_timeout: float = DEFAULT_SMTP_TIMEOUT,
) -> ValidationResult:

    mode = mode.lower()

    if mode not in {"fast", "standard", "deep"}:
        raise ValueError(
            "mode must be: fast, standard or deep"
        )

    normalized = normalize_email(email)

    local = None
    domain = None
    ascii_domain = None

    if "@" in normalized:
        local, domain = normalized.rsplit("@", 1)
        ascii_domain = domain_to_ascii(domain)

    result = ValidationResult(
        input=email,
        normalized=normalized,
        local_part=local,
        domain=domain,
        ascii_domain=ascii_domain,
        mode=mode,
    )

    checks: list[Check] = []

    # ------------------------------------------------------------------
    # SYNTAX
    # ------------------------------------------------------------------

    syntax = timed_check(
        "syntax",
        check_syntax,
        normalized,
    )

    checks.append(syntax)

    if syntax.status == "fail":
        result.checks = [
            asdict(check)
            for check in checks
        ]

        result.scores = {
            "syntax": 0.0,
            "domain": 0.0,
            "mail_server": 0.0,
            "mailbox": 0.0,
            "trust": 0.0,
        }

        result.confidence = 1.0
        result.verdict = "invalid"

        return result

    # ------------------------------------------------------------------
    # LOCAL CHECKS
    # ------------------------------------------------------------------

    checks.append(
        timed_check(
            "unicode_security",
            check_unicode_security,
            normalized,
        )
    )

    checks.append(
        timed_check(
            "role_account",
            check_role_account,
            local,
        )
    )

    checks.append(
        timed_check(
            "disposable",
            check_disposable,
            domain,
        )
    )

    checks.append(
        timed_check(
            "free_provider",
            check_free_provider,
            domain,
        )
    )

    typo = timed_check(
        "domain_typo",
        check_typo,
        domain,
    )

    checks.append(typo)

    if typo.status == "warning":
        suggestion = typo.details.get("suggestion")

        if suggestion:
            result.suggestions.append(
                f"Did you mean {local}@{suggestion}?"
            )

    if mode == "fast":
        scores, confidence = calculate_scores(
            checks,
            mode,
        )

        result.scores = scores
        result.confidence = confidence
        result.verdict = choose_verdict(
            scores,
            checks,
        )

        result.checks = [
            asdict(check)
            for check in checks
        ]

        return result

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    domain_target = ascii_domain or domain

    checks.append(
        timed_check(
            "domain_exists",
            check_domain_exists,
            domain_target,
            dns_timeout,
        )
    )

    mx_check = timed_check(
        "mx",
        get_mx_records,
        domain_target,
        dns_timeout,
    )

    checks.append(mx_check)

    mx_records = mx_check.details.get(
        "mx_records",
        [],
    )

    checks.append(
        timed_check(
            "provider",
            detect_provider,
            mx_records,
        )
    )

    checks.append(
        timed_check(
            "spf",
            check_spf,
            domain_target,
            dns_timeout,
        )
    )

    checks.append(
        timed_check(
            "dmarc",
            check_dmarc,
            domain_target,
            dns_timeout,
        )
    )

    checks.append(
        timed_check(
            "mta_sts",
            check_mta_sts,
            domain_target,
            dns_timeout,
        )
    )

    checks.append(
        timed_check(
            "tls_rpt",
            check_tls_rpt,
            domain_target,
            dns_timeout,
        )
    )

    if mode == "deep" and mx_records:

        # --------------------------------------------------------------
        # SMTP
        # --------------------------------------------------------------

        smtp_check = timed_check(
            "smtp",
            check_smtp,
            normalized,
            mx_records,
            smtp_timeout,
        )

        checks.append(smtp_check)

        # Only bother checking catch-all when SMTP probing works enough
        # to make the result meaningful.
        if smtp_check.status in {
            "pass",
            "unknown",
        }:
            checks.append(
                timed_check(
                    "catch_all",
                    check_catch_all,
                    domain_target,
                    mx_records,
                    smtp_timeout,
                )
            )

    # ------------------------------------------------------------------
    # WARNINGS
    # ------------------------------------------------------------------

    for check in checks:

        if check.status == "warning":
            result.warnings.append(
                f"{check.name}: warning"
            )

        if check.status == "error":
            result.warnings.append(
                f"{check.name}: check failed"
            )

    # ------------------------------------------------------------------
    # FINAL SCORE
    # ------------------------------------------------------------------

    scores, confidence = calculate_scores(
        checks,
        mode,
    )

    result.scores = scores
    result.confidence = confidence

    result.verdict = choose_verdict(
        scores,
        checks,
    )

    result.checks = [
        asdict(check)
        for check in checks
    ]

    result.metadata = {
        "validator": "MailProbe",
        "version": VERSION,
        "smtp_verification_is_definitive": False,
    }

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "MailProbe - explainable email validation engine"
        )
    )

    parser.add_argument(
        "email",
        help="Email address to validate",
    )

    parser.add_argument(
        "--mode",
        choices=[
            "fast",
            "standard",
            "deep",
        ],
        default="standard",
        help="Validation depth",
    )

    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=DEFAULT_DNS_TIMEOUT,
        help="DNS timeout in seconds",
    )

    parser.add_argument(
        "--smtp-timeout",
        type=float,
        default=DEFAULT_SMTP_TIMEOUT,
        help="SMTP timeout in seconds",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"MailProbe {VERSION}",
    )

    args = parser.parse_args()

    try:
        result = validate_email(
            args.email,
            mode=args.mode,
            dns_timeout=args.dns_timeout,
            smtp_timeout=args.smtp_timeout,
        )

        output = asdict(result)

        print(
            json.dumps(
                output,
                indent=2 if args.pretty else None,
                ensure_ascii=False,
            )
        )

    except KeyboardInterrupt:
        print(
            "\nValidation cancelled.",
            file=sys.stderr,
        )

        sys.exit(130)

    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": str(exc),
                }
            ),
            file=sys.stderr,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
