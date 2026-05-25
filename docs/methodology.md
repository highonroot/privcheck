# Methodology

PrivCheck follows the same enumeration workflow used throughout the Linux PrivEsc writeups:

1. Identity
2. Sudo
3. SUID / SGID
4. Capabilities
5. Cron Jobs
6. Writable Files and Directories
7. PATH
8. Credential Exposure
9. Sensitive Files
10. Processes and Services

The goal is identifying suspicious trust relationships and potential escalation paths that deserve investigation.

PrivCheck does not exploit vulnerabilities. It automates common enumeration checks and highlights findings for manual review.
