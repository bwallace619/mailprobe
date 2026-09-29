# MailProbe

**An explainable email validation engine that tells you why an address looks valid — not just `true` or `false`.**

MailProbe is a Python-based email validation tool designed to go further than a basic regex check. It inspects syntax, DNS, MX infrastructure, disposable domains, suspicious Unicode, domain typos, email authentication records, provider information and, optionally, SMTP behaviour.

## Features

- Syntax validation and normalization
- IDN / Punycode support
- Unicode mixed-script and homoglyph checks
- Invisible/control-character detection
- Role-account detection
- Disposable-email detection
- Common-domain typo suggestions
- DNS existence checks
- MX and null-MX validation
- A-record fallback detection
- Mail-provider detection
- SPF, DMARC, MTA-STS and TLS-RPT checks
- SMTP recipient probing
- Catch-all detection
- Explainable confidence scoring
- FAST, STANDARD and DEEP modes
- JSON CLI output

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/mailprobe.git
cd mailprobe
pip install -r requirements.txt
```

## Usage

```bash
python mailprobe.py test@example.com --pretty
```

Fast local-only checks:

```bash
python mailprobe.py test@gmail.com --mode fast --pretty
```

Standard DNS and infrastructure checks:

```bash
python mailprobe.py test@gmail.com --mode standard --pretty
```

Deep validation including SMTP probing:

```bash
python mailprobe.py test@gmail.com --mode deep --pretty
```

## Validation modes

### FAST

Runs local checks without network requests:

- syntax
- normalization
- Unicode security
- role-account detection
- disposable-domain detection
- free-provider detection
- typo suggestions

### STANDARD

Everything in FAST, plus:

- domain existence
- MX records
- provider detection
- SPF
- DMARC
- MTA-STS
- TLS-RPT

### DEEP

Everything in STANDARD, plus:

- SMTP connection attempts
- EHLO
- STARTTLS detection
- MAIL FROM
- RCPT TO
- mailbox-response classification
- catch-all probing

## Verdicts

MailProbe avoids reducing uncertain results to a misleading boolean.

Possible verdicts:

```text
deliverable
probably_deliverable
unknown
probably_undeliverable
undeliverable
invalid
```

## Example output

```json
{
  "input": "test@gmail.com",
  "normalized": "test@gmail.com",
  "local_part": "test",
  "domain": "gmail.com",
  "ascii_domain": "gmail.com",
  "mode": "standard",
  "verdict": "probably_deliverable",
  "confidence": 0.98,
  "scores": {
    "syntax": 1.0,
    "domain": 1.0,
    "mail_server": 1.0,
    "mailbox": 0.5,
    "trust": 1.0
  }
}
```

Each check also includes a status, details and execution time.

## Why not just regex?

A regex can only tell you whether an address looks structurally plausible. It cannot tell you whether the domain exists, whether it accepts mail, whether it has MX records, whether it is disposable, whether it contains suspicious Unicode, or whether the server appears to accept the recipient.

MailProbe exposes these signals independently so developers can see why an address received a particular result.

## Unicode security

MailProbe looks for suspicious email-domain behaviour such as:

- mixed writing systems
- Cyrillic/Greek characters that resemble Latin characters
- invisible Unicode characters
- control characters

This is useful for identifying possible IDN homograph or spoofing risks.

## SMTP limitations

SMTP verification is not definitive. Major providers may deliberately obscure whether a mailbox exists by accepting nonexistent recipients, rejecting mailbox enumeration, greylisting requests, rate limiting, blocking residential IPs, or varying behaviour by sender reputation.

MailProbe therefore returns `unknown` when the evidence is weak instead of pretending certainty.

## Responsible use

Do not use MailProbe to aggressively enumerate mailboxes, harvest addresses, bypass provider protections or send spam. Large-scale SMTP probing can cause providers to rate-limit or block your IP.

MailProbe is intended for legitimate validation, development, research and security testing.

## Python usage

```python
from mailprobe import validate_email

result = validate_email("test@example.com", mode="standard")
print(result.verdict)
print(result.confidence)
```

## Requirements

- Python 3.10+
- dnspython

## Planned features

- asynchronous DNS and SMTP checks
- bulk CSV/JSONL validation
- larger disposable-domain database
- plugin architecture
- FastAPI server mode
- caching
- DNSSEC and BIMI checks
- provider-specific SMTP strategies
- configurable scoring rules
- test suite and benchmarks
- PyPI package

## Contributing

Contributions are welcome, especially for provider fingerprints, disposable-domain data, Unicode-security improvements, typo detection, tests and documentation.

Please do not post private email addresses in public issues.

## License

MIT

---

**MailProbe** — explainable email validation instead of another regex.
