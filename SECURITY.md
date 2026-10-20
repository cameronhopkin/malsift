# Security Policy

## Reporting a vulnerability

Open a GitHub security advisory on the repository, or contact the maintainer through the
address listed on the repository profile. Include a description, affected version, and a
minimal reproduction that **does not require sharing a live malware sample**.

## Scope

In scope: the analysis pipeline, isolation configuration, content guard, preprocessor,
and report builder.

Out of scope: vulnerabilities in third-party dependencies (report those upstream), and
the inherent risk of running untrusted code during dynamic detonation, which is
documented in [DISCLAIMER.md](DISCLAIMER.md).

## Handling test material

Do not attach live malware to reports. A synthetic reproduction or a hash plus a
description is sufficient.
