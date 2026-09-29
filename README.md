# MailProbe

An explainable email validation engine that tells you why an email address looks valid — not just `true` or `false`.

MailProbe is a Python-based email validation tool designed to go further than basic regex validation. It can inspect syntax, DNS records, mail infrastructure, disposable domains, suspicious Unicode characters, provider information, domain typos, email authentication records, and optionally perform SMTP-level checks.

The goal is to provide a detailed validation report with clear signals, warnings, and confidence scores.

## Features

MailProbe currently supports:

- Email syntax validation
- Email normalization
- IDN and Punycode domain handling
- Unicode security checks
- Mixed-script detection
- Homoglyph detection
- Invisible/control character detection
- Role account detection
- Disposable email detection
- Free email provider detection
- Domain typo suggestions
- DNS existence checks
- MX record validation
- Null MX detection
- A-record mail fallback detection
- Mail provider detection
- SPF detection
- DMARC detection
- MTA-STS detection
- TLS-RPT detection
- SMTP mailbox probing
- Catch-all domain detection
- Confidence scoring
- Detailed JSON output
- Three validation modes

## Why MailProbe?

A lot of email validation examples look like this:

```python
if re.match(pattern, email):
    print("Valid")
```

That only tells you whether the address matches a pattern.

It does not tell you whether:

- the domain exists
- the domain accepts email
- MX servers are configured
- the domain is disposable
- the address contains suspicious Unicode
- the user probably mistyped the domain
- the mail server accepts the recipient
- the domain accepts every possible recipient
- the domain has SPF or DMARC configured

MailProbe tries to expose those signals individually instead of hiding everything behind a single boolean.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/mailprobe.git
cd mailprobe
```

Install the dependency:

```bash
pip install dnspython
```

Then run MailProbe:

```bash
python mailprobe.py test@example.com
```

## Usage

Basic validation:

```bash
python mailprobe.py test@example.com
```

Pretty-print the JSON output:

```bash
python mailprobe.py test@example.com --pretty
```

Choose a validation mode:

```bash
python mailprobe.py test@example.com --mode fast
```

```bash
python mailprobe.py test@example.com --mode standard
```

```bash
python mailprobe.py test@example.com --mode deep
```

## Validation Modes

### FAST

Performs local checks without making network requests.

Includes:

- syntax validation
- normalization
- Unicode security checks
- role account detection
- disposable domain detection
- free-provider detection
- typo suggestions

Example:

```bash
python mailprobe.py test@gmail.com --mode fast --pretty
```

### STANDARD

Includes everything from FAST plus domain and mail infrastructure checks.

Includes:

- DNS lookup
- domain existence
- MX records
- provider detection
- SPF
- DMARC
- MTA-STS
- TLS-RPT

Example:

```bash
python mailprobe.py test@gmail.com --mode standard --pretty
```

### DEEP

Includes everything from STANDARD plus SMTP-level probing.

Includes:

- SMTP connection attempts
- `EHLO`
- `STARTTLS` detection
- `MAIL FROM`
- `RCPT TO`
- mailbox response classification
- catch-all detection

Example:

```bash
python mailprobe.py test@gmail.com --mode deep --pretty
```

## Example Output

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
  },
  "warnings": [],
  "suggestions": [],
  "metadata": {
    "validator": "MailProbe",
    "version": "1.0.0",
    "smtp_verification_is_definitive": false
  }
}
```

Each individual check also includes its own status, details, and execution time.

Example:

```json
{
  "name": "mx",
  "status": "pass",
  "details": {
    "mx_records": [
      {
        "priority": 5,
        "host": "gmail-smtp-in.l.google.com"
      }
    ],
    "null_mx": false
  },
  "duration_ms": 28.41
}
```

## Verdicts

MailProbe does not reduce every result to simply valid or invalid.

Possible verdicts include:

```text
deliverable
probably_deliverable
unknown
probably_undeliverable
undeliverable
invalid
```

This is intentional.

Email validation is not always deterministic, especially when SMTP servers deliberately hide whether an individual mailbox exists.

## Domain Typo Detection

MailProbe can detect common domain mistakes.

For example:

```text
user@gmial.com
```

may generate:

```json
{
  "suggestion": "gmail.com",
  "distance": 2,
  "similarity": 0.9
}
```

and:

```text
Did you mean user@gmail.com?
```

## Unicode Security

Email addresses can contain Unicode characters that visually resemble normal Latin characters.

For example, a malicious domain could potentially contain a Cyrillic character that looks almost identical to a Latin character.

MailProbe checks for:

- mixed scripts
- suspicious confusable characters
- invisible characters
- Unicode control characters

A suspicious result might look like:

```json
{
  "mixed_scripts": true,
  "confusable_characters": [
    {
      "character": "а",
      "looks_like": "a",
      "unicode_name": "CYRILLIC SMALL LETTER A"
    }
  ],
  "risk": "elevated"
}
```

## Role Accounts

MailProbe can identify addresses commonly used as shared or organisational mailboxes.

Examples include:

```text
admin@example.com
support@example.com
billing@example.com
security@example.com
postmaster@example.com
abuse@example.com
```

These are not invalid addresses.

They are simply classified separately because they may behave differently from personal inboxes.

## Disposable Emails

MailProbe includes basic detection for known temporary and disposable email providers.

Examples include providers such as:

```text
mailinator.com
guerrillamail.com
yopmail.com
maildrop.cc
```

The built-in list is intentionally small for now and can be expanded into a community-maintained dataset later.

## Mail Provider Detection

MailProbe attempts to identify the mail provider based on MX infrastructure.

Currently recognised providers include:

- Google Workspace / Gmail
- Microsoft 365 / Outlook
- Proton Mail
- Fastmail
- Zoho Mail
- Yahoo
- Apple iCloud

Unknown infrastructure is reported as:

```text
Unknown / self-hosted
```

## Email Authentication

MailProbe can inspect several domain-level email security mechanisms.

### SPF

Checks for:

```text
v=spf1
```

TXT records.

### DMARC

Checks:

```text
_dmarc.example.com
```

for:

```text
v=DMARC1
```

records.

### MTA-STS

Checks:

```text
_mta-sts.example.com
```

for an MTA-STS declaration.

### TLS-RPT

Checks:

```text
_smtp._tls.example.com
```

for TLS reporting configuration.

## SMTP Verification

DEEP mode can attempt to communicate directly with the destination mail server.

A simplified SMTP exchange looks like:

```text
CONNECT
EHLO
STARTTLS
MAIL FROM
RCPT TO
```

The response to `RCPT TO` may provide evidence about whether the destination mailbox is accepted.

However, SMTP verification should never be treated as absolute proof that an inbox exists.

Major providers may:

- accept nonexistent recipients
- reject mailbox enumeration
- temporarily defer requests
- greylist requests
- rate-limit connections
- block residential IP ranges
- behave differently depending on sender reputation
- require retry attempts

Because of this, MailProbe deliberately supports an `unknown` state.

## Catch-All Detection

Some domains accept email sent to any address.

For example:

```text
this-address-does-not-exist-123@example.com
```

may still receive a successful SMTP response.

MailProbe can generate random addresses and probe them to estimate whether a domain is configured as catch-all.

A catch-all result means SMTP acceptance cannot reliably prove that the requested mailbox exists.

## Confidence Scores

MailProbe separates several validation dimensions.

Example:

```json
{
  "syntax": 1.0,
  "domain": 1.0,
  "mail_server": 1.0,
  "mailbox": 0.5,
  "trust": 0.95
}
```

This makes the result easier to inspect than a single unexplained score.

### Syntax

Measures whether the address itself appears structurally valid.

### Domain

Measures whether the domain exists.

### Mail Server

Measures whether usable mail infrastructure appears to exist.

### Mailbox

Represents available evidence about the individual recipient.

This score is intentionally conservative.

### Trust

Contains additional signals such as:

- disposable providers
- suspicious Unicode
- likely domain typos
- email authentication configuration

## Python Usage

MailProbe can also be imported directly.

```python
from mailprobe import validate_email

result = validate_email(
    "test@example.com",
    mode="standard"
)

print(result.verdict)
print(result.confidence)
```

For deeper checks:

```python
result = validate_email(
    "test@example.com",
    mode="deep"
)
```

## Timeouts

DNS timeout:

```bash
python mailprobe.py test@example.com \
    --dns-timeout 6
```

SMTP timeout:

```bash
python mailprobe.py test@example.com \
    --mode deep \
    --smtp-timeout 10
```

## Important Limitations

MailProbe cannot guarantee that an email address belongs to a real person.

It also cannot guarantee that a message will successfully reach an inbox.

Email deliverability depends on significantly more than recipient validation, including:

- sender reputation
- IP reputation
- spam filtering
- DKIM
- SPF alignment
- DMARC
- message content
- sending patterns
- provider-specific policies

SMTP recipient probing is also intentionally restricted or obscured by many major providers.

MailProbe therefore reports uncertainty rather than pretending uncertain results are definitive.

## Responsible Usage

SMTP probing should be used conservatively.

Do not use MailProbe to:

- aggressively enumerate mailboxes
- bypass provider protections
- send spam
- harvest email addresses
- repeatedly probe large numbers of recipients without permission

Providers may rate-limit or block systems making excessive SMTP requests.

MailProbe is intended for legitimate validation, development, research, and security-related use.

## Planned Features

Possible future additions include:

- larger disposable-domain database
- community-maintained provider fingerprints
- asynchronous DNS validation
- asynchronous SMTP probing
- bulk CSV validation
- JSONL output
- configurable scoring rules
- plugin system
- REST API
- FastAPI server mode
- Docker image
- caching
- Redis support
- DNSSEC inspection
- BIMI inspection
- more advanced IDN homograph detection
- provider-specific SMTP strategies
- domain reputation signals
- CLI table output
- benchmark suite
- Python package release
- GitHub Actions tests

## Project Structure

The current version is intentionally distributed as a single Python script.

This makes it easy to:

- inspect
- modify
- copy
- test
- contribute to

As MailProbe grows, it may eventually be separated into components such as:

```text
mailprobe/
├── parser/
├── dns/
├── smtp/
├── intelligence/
├── security/
├── scoring/
└── providers/
```

## Contributing

Contributions are welcome.

Useful areas for contribution include:

- additional disposable domains
- mail-provider fingerprints
- Unicode security improvements
- typo detection
- DNS handling
- SMTP behaviour research
- tests
- documentation
- performance improvements

If you find a false positive or false negative, opening an issue with the affected domain and the relevant validation output is particularly useful.

Please avoid posting private email addresses in public issues.

## Requirements

- Python 3.10+
- dnspython

Install dependencies with:

```bash
pip install dnspython
```

## License

MIT

You are free to use, modify, distribute, and contribute to MailProbe under the terms of the MIT License.

## Disclaimer

MailProbe provides validation signals and estimates.

Its results should not be treated as definitive proof that:

- a mailbox exists
- a person controls an address
- a message will be delivered
- a domain is trustworthy

Use the output as evidence rather than certainty.

---

**MailProbe**

Explainable email validation instead of another regex.
