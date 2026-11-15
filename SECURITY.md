# Security Policy

## Reporting a Vulnerability

Do not open a public issue or pull request for security vulnerabilities in
`Pigbibi/PrGovernance`, its reusable GitHub Action, or its local hook track.

Use GitHub Private Vulnerability Reporting for this repository:

- Open the **Security** tab on `Pigbibi/PrGovernance`.
- Select **Advisories** -> **Report a vulnerability**.

Include the affected path, reproduction steps, and the security impact (such as
receipt validation bypass, secret-scan evasion, or unsafe workflow execution).

## Disclosure

- Never include real tokens, credentials, private hostnames, or account IDs in
  reports or test cases.
- Fixes are reviewed and released through standard pull request checks before any
  downstream commit pins are updated.
