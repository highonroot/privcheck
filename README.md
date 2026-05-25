# PrivCheck

A Linux security auditing script built from first-principles Linux PrivEsc learning.

PrivCheck automates common privilege escalation enumeration checks while preserving the reasoning behind them. It focuses on identifying suspicious conditions that may lead to privilege escalation and maps directly to the concepts covered throughout my Linux PrivEsc writeups.

The goal is not exploitation.

The goal is understanding where trust breaks, identifying misconfigurations, and helping investigate potential escalation paths systematically.

---

## What It Checks

PrivCheck audits:

- Identity and privileged groups
- sudo permissions
- SUID / SGID binaries
- Linux capabilities
- Cron jobs
- Writable files and directories
- PATH vulnerabilities
- Credential exposure
- Sensitive file permissions
- Processes and listening services

Each check corresponds to a privilege escalation concept covered in the accompanying Linux PrivEsc writeups.

---

## Why It Exists

Linux PrivEsc relies heavily on enumeration.

Running the same checks manually is useful for learning, but repetitive in practice.

PrivCheck automates those checks while keeping the methodology simple, transparent, and aligned with the Linux PrivEsc concepts covered in the accompanying writeups.

---

## Installation

```bash
git clone https://github.com/highonroot/privcheck.git
cd privcheck
chmod +x privcheck.sh
```

---

## Usage

Run PrivCheck:

```bash
./privcheck.sh
```

Show remediation guidance:

```bash
./privcheck.sh --fix
```
> Tested on Debian-based Linux distributions. Other environments may produce different results.

---

## Notes

- PrivCheck is an auditing helper, not a vulnerability scanner.
- Findings indicate conditions worth investigating and do not automatically confirm a privilege escalation path.
- Manual verification is always required.

---

## Additional Resources

- Methodology: [docs/methodology.md](docs/methodology.md)
- Roadmap: [docs/roadmap.md](docs/roadmap.md)
