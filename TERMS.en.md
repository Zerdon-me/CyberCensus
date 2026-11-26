# CyberCensus Terms of Use & Disclaimer

> Effective date: 2026-11-26
> Applies to: CyberCensus source code, executables, packages, documentation, and bundled tools (the "Software").

**Read these terms before using the Software. Downloading, installing, running, copying, or otherwise using the Software means you have read, understood, and agreed to these terms. If you do not agree, stop using the Software and delete it immediately.**

## 1. Definitions

- **"Software"**: the CyberCensus project and the software, scripts, documentation, and materials provided by its authors and contributors.
- **"User"**: any individual or organization that downloads, installs, runs, or otherwise uses the Software.
- **"Target"**: any domain, IP address, network range, organization name, or related asset that the User inputs, probes, scans, or analyzes with the Software.
- **"Authors and Contributors"**: the copyright holders, maintainers, and code contributors of CyberCensus.

## 2. Authorization

2.1 The Software may only be used against:

1. assets owned by the User;
2. assets for which the User has obtained explicit, written, and traceable authorization from the asset owner;
3. scenarios expressly permitted by applicable law or regulation.

2.2 The User must confirm the scope of authorization (domains, IPs, ports, time window, testing methods) before testing and must retain the authorization documentation. If authorization is unclear, the Target must be treated as **unauthorized**.

2.3 The User is responsible for determining whether their use complies with applicable laws, regulations, industry requirements, and agreements with the Target. The Authors and Contributors do not grant authorization and do not verify the User's authorization status.

## 3. Prohibited Conduct

The User **must not** use or assist others in using the Software for:

1. scanning, probing, mapping, vulnerability verification, or any active access against Targets without explicit written authorization;
2. unauthorized intrusion, access, privilege escalation, lateral movement, persistence, or damage to computer information systems;
3. denial-of-service attacks, resource exhaustion, stress testing, or high-frequency/high-concurrency activity that affects the Target's normal operations;
4. password brute-forcing, credential stuffing, captcha bypass, rate-limit/risk-control bypass, or other circumvention of security mechanisms;
5. stealing, altering, deleting, or disclosing others' data, trade secrets, personal information, or state secrets;
6. creating, distributing, or implanting malware, ransomware, backdoors, or attack tools;
7. evading detection, concealing traces, forging origin, or impersonating others;
8. packaging, marketing, or reselling the Software as a "one-click attack", "authorization-free penetration", or other illegal or misleading service;
9. violating the terms of service of the Target, cloud providers, reconnaissance platforms, or third-party data sources;
10. removing, hiding, or altering copyright, license, disclaimer, or attribution notices;
11. using or distributing the Software in violation of export controls, sanctions, or other applicable law;
12. any other activity that violates law, public order, or the rights of others.

## 4. Active Scanning and Resource Impact

4.1 The Software is passive-first by default. Enabling `--active`, `--cscan`, `--scan-asn`, `--verify`, `--probe-found`, or similar options causes real requests to the Target.

4.2 The User must control concurrency, port ranges, request rates, and time windows to avoid affecting the Target, its network, or third-party services. The User bears all consequences of active scanning, including service disruption, blocking, complaints, or claims.

4.3 For government, critical information infrastructure, healthcare, financial, energy, transportation, and other sensitive Targets, the User must adopt more conservative settings and operate only within legal and authorized bounds.

## 5. Data, Credentials, and Privacy

5.1 The User is responsible for safeguarding platform API keys, account credentials, authorization documents, scan results, and reports.

5.2 The User must not use the Software to collect, store, or disclose personal information, sensitive data, or trade secrets beyond the authorized scope. Where processing is necessary, the User must comply with applicable data protection and privacy laws.

5.3 The User bears all consequences of credential leakage, improper storage, unauthorized disclosure, or misuse of data.

## 6. Third-Party Platforms and Data Sources

6.1 The Software may optionally integrate third-party platforms (FOFA, 0.zone, Hunter, DayDayMap, ZoomEye, 360 Quake, Shodan, Censys) and public sources such as search engines, certificate transparency logs, and DNS/WHOIS/RDAP.

6.2 Use of third-party platforms is subject to their own terms, quotas, billing, and privacy policies. The User must comply with them and bears related costs and liabilities.

6.3 Third-party data may be inaccurate, incomplete, delayed, or poisoned. The Authors and Contributors make no warranty regarding its accuracy, legality, or availability.

## 7. Intellectual Property and License

7.1 The Software is released under the Apache License 2.0. Rights and obligations are governed by [LICENSE](LICENSE) and [NOTICE](NOTICE).

7.2 These terms do not modify or replace any rights granted by Apache-2.0. If these terms conflict with Apache-2.0, Apache-2.0 prevails.

7.3 The "CyberCensus" name, logo, and related marks belong to the project authors. You may not imply endorsement by the authors without permission.

## 8. No Warranty

The Software is provided **"AS IS"** and **"AS AVAILABLE"**, without any express or implied warranty, including but not limited to merchantability, fitness for a particular purpose, non-infringement, accuracy, completeness, freedom from viruses, uninterrupted operation, or error correction.

The Authors and Contributors do not warrant that the Software will meet the User's requirements or that scan results, attribution decisions, evidence grading, or reports will be completely accurate.

## 9. Limitation of Liability

To the maximum extent permitted by law, the Authors and Contributors are not liable for any direct, indirect, incidental, special, punitive, or consequential damages arising from the use of or inability to use the Software, including but not limited to:

- loss of data, business interruption, loss of goodwill, or loss of profits;
- claims by the Target, administrative penalties, criminal liability, or third-party claims;
- losses caused by scanning, probing, misclassification, missed findings, data errors, or third-party platform behavior;
- consequences of the User's violation of authorization, law, or these terms.

## 10. Indemnification

If the User's use of the Software or conduct causes the Authors and Contributors to face third-party claims, complaints, investigations, penalties, or losses, the User shall indemnify them, including reasonable legal fees, litigation costs, and travel expenses.

## 11. Changes and Termination

11.1 The Authors and Contributors may update these terms with new releases. Updated terms take effect when published. Continued use constitutes acceptance.

11.2 If the User violates these terms or applicable law, the Authors and Contributors may refuse support, stop distribution, or terminate the license to the extent permitted by law.

## 12. Miscellaneous

12.1 If any provision is held invalid or unenforceable, the remaining provisions remain in effect.

12.2 These terms constitute the entire agreement between the User and the Authors regarding the Software and supersede prior oral or written statements on the same subject.

12.3 These terms are governed by the laws of the People's Republic of China (excluding conflict-of-law rules). Disputes shall be submitted to a competent court at the authors' location, unless mandatory law provides otherwise.

12.4 These terms do not constitute legal advice. The User should consult a qualified lawyer for their specific situation.

## 13. Contact

- Security and authorization boundaries: [SECURITY.md](SECURITY.md)
- Commercial services: [COMMERCIAL.md](COMMERCIAL.md)
- Project: https://github.com/Zerdon-me/CyberCensus
