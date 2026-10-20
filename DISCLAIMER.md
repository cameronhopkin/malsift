# Disclaimer and Safe-Handling Policy

MalSift is **defensive security tooling** for analyzing malware you are **lawfully
authorized** to analyze. By using it you accept the following.

## Authorized use only

Use MalSift only on samples you own or have explicit written authorization to examine.
You are responsible for complying with all applicable laws, contracts, and program
rules. The authors provide the software "AS IS" with no warranty and accept no liability
for misuse (see [LICENSE](LICENSE)).

## Never commit live samples

Do not add live malware, extracted payloads, or their byte content to this repository or
to any report you share. `samples/` and `reports/` are gitignored and a pre-commit hook
blocks sample commits. When reporting an issue, use a hash and a description, or a
synthetic reproduction, never a live sample.

## Static parsing on the host

By default MalSift parses samples directly on the analysis host. Use `--isolate docker`
for untrusted samples: parsing then happens in a network-less, read-only, capability-free
container with a seccomp allowlist. A container shares the host kernel; it is a
boundary for *parsing* hostile files, not for executing them.

## Detonation safety

The dynamic tier is a documented stub. If you complete it:
- Detonate only inside an isolated microVM (separate guest kernel) with no reachable path
  to production networks, credentials, or data.
- Treat the analysis host as disposable.
- Assume any sample can attempt sandbox escape and anti-analysis.

## Content handling

MalSift deliberately **does not surface** adversarial content embedded in samples. It
strips or neutralizes injection-shaped bait and records metadata-only markers. It ships
**no** dictionary of sensitive subject matter. If you wire in a high-risk classifier, it
must likewise emit metadata only, never the flagged content.

## No offensive capability

MalSift analyzes samples. It does not generate malware, exploits, or evasion tooling, and
contributions that add such capability will be rejected.
