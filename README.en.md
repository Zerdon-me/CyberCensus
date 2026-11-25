<p align="center"><img src="docs/logo.svg" width="112" alt="CyberCensus logo"></p>

# CyberCensus

<p align="center"><b>Find every exposed asset. Prove every attribution.</b></p>

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4.svg)](#)

**Internet exposure-surface mapping for an organization name, domain, IP, or CIDR.**

Given a target, CyberCensus discovers publicly exposed assets and classifies them into **Confirmed / Suspected / Rejected** using an auditable A/B/C evidence model. The goal is simple: **no false positives in the confirmed list.**

> ⚠️ **Authorized use only.** Use it only against assets you own or are written-authorized to assess. The default mode is passive; active scanning touches the target and is opt-in.

## What it does

- Discovery from an organization name: search-engine bootstrapping → anchor domains → certificate transparency → DNS/whois/IP pivots
- 8 optional cyber-space mapping platforms: FOFA, 0.zone, Hunter, DayDayMap, ZoomEye, 360 Quake, Shodan, Censys (bring your own API key)
- Attribution evidence: ICP filing number, TLS certificate O=, unified social credit code, RDAP registrant, owned ASN, LEI/VAT/DUNS/EIN, analytics IDs, domain-verification tokens, contact details, footer authority, reciprocal links
- Classification: **Confirmed = A ≥ 1 or B ≥ 2**, Suspected, Rejected (with a reason)
- Passive DNS/cert pivots, certificate SAN siblings, MX/SPF domains
- Optional active: port scanning, web fingerprinting, sensitive paths, ASN netblock expansion
- External engines: subfinder / httpx / wafw00f / nuclei (bundled in the full package, updatable)
- Reports: HTML / PDF / Word / TXT / Markdown / CSV / JSON, plus an interactive asset relationship graph
- Continuous monitoring (`--watch`), baseline diffing, Webhook alerts
- GUI: asset table with sorting, search, multi-select, bulk reclassification, copy URLs/hosts, export selected CSV

## Quick start

**Windows:** download `CyberCensus-win64.zip` from **Releases**, extract, and double-click `CyberCensus.exe`. No Python installation is required.

**Linux (x86_64, CLI):** download `CyberCensus-linux-x86_64.tar.gz`, extract, run `./install.sh` once (creates a venv), then `./cybercensus -n "Org Name"`. The archive bundles Linux builds of subfinder / httpx / nuclei and nuclei-templates. The GUI is Windows-only; on a Linux desktop you can run it from source with `pip3 install customtkinter && python3 asm_gui.pyw`.

From source:

```bat
pip install -r requirements.txt customtkinter
python asm_gui.pyw
```

CLI:

```bat
python cybercensus.py -d example.com
python cybercensus.py -n "Example Corporation"
python cybercensus.py -d example.com --verify
python cybercensus.py -d example.com --active --top 100   # authorized targets only
```

Run tests (offline):

```bat
python -m unittest discover tests -v
```

## Evidence grading

| Level | Examples |
|---|---|
| **A (strong)** | ICP filing number, certificate O=, credit code, RDAP registrant, owned ASN, LEI, subdomain of a known domain |
| **B (medium)** | analytics/pixel ID, verification token, contact email/phone, footer authority, reciprocal link, icon hash, multiple-platform cross-hit |
| **C (weak)** | same anchor IP, platform IP/ASN/keyword hit |

Historical data and platform-only hits are treated as leads; live verification decides the final class.

## Documentation

The full documentation is currently in Chinese: [README.md](README.md). It covers every CLI flag, data source, evidence rule, report format, and known limitations.

## Legal & security

- [SECURITY.md](SECURITY.md) — authorized-use policy and private vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and contribution rules
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — dependency and bundled-tool licenses
- [COMMERCIAL.md](COMMERCIAL.md) — open core + commercial services boundary
- [LICENSE](LICENSE) — Apache-2.0

Provided “as is”, without warranty. You are responsible for authorization, legality, and scan rate.
