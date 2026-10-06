# LAS — Local Admin Scanner

> A security and infrastructure auditing tool for discovering, analyzing, and remediating local privileged access on Windows computers in Active Directory environments.

LAS helps infrastructure, system administration, and security teams answer a practical question: **who has local administrative access on which domain computers right now?**

The system discovers computers from Active Directory, checks connectivity, collects local group membership, optionally expands domain groups, calculates risk, stores scan artifacts, and provides Web UI, API, export, comparison, and controlled remediation.

## Table of Contents
- Features
- How LAS Works
- Architecture
- Requirements
- Installation
- Running the Application
- Scan Configuration
- Collection Methods
- Web UI and Summary
- Scan Comparison
- Remediation
- Export
- HTTP API
- Logging
- Performance
- Security
- Troubleshooting
- Project Structure
- Recommended Operating Workflow
- Limitations
- Documentation

## Features

### Local privileged access auditing
LAS collects members of Windows local groups including Administrators, Remote Desktop Users, Distributed COM Users, Remote Management Users, and additional groups selected by the operator.

For discovered access it can record account, object type, computer, local group, direct or group-based access, and risk-related attributes.

### Active Directory integration
- computer discovery through LDAP;
- separate workstation and server OUs;
- include/exclude patterns;
- operating-system filtering;
- LDAP/Global Catalog group expansion;
- limits for group expansion depth and volume.

### Adaptive collection
The collection order supports WinRM/PowerShell, RPC/SMB fallback, and optional WMI. This allows LAS to collect useful information from heterogeneous Windows environments.

### Performance controls
Controls include worker count, network concurrency, RPC concurrency, probe timeout, host hard timeout, LDAP/GC workers, and group-expansion limits.

### Analytics
Summary provides overall metrics, risky machines, common administrator accounts, account-to-machine distribution, machine details, filtering, heatmap, scan comparison, and export.

### Remediation
Selected accounts can be removed from local groups through the Web UI or through a generated PowerShell script.

The exported remediation script uses WinRM first and remote ADSI/RPC fallback when WinRM fails. The result is verified after deletion.

## How LAS Works

```text
Active Directory
 |
 v
LDAP / Global Catalog
 |
 v
Computer inventory
 |
 +---- include/exclude/OS filters
 |
 v
Connectivity probes
 |
 +---- WinRM
 +---- SMB/RPC
 +---- RDP
 |
 v
Remote collection
 |
 +---- PowerShell / WinRM
 +---- RPC / SMB
 +---- WMI (optional)
 |
 v
Local group memberships
 |
 v
LDAP/GC group expansion
 |
 v
Risk calculation
 |
 +---- JSON
 +---- CSV
 +---- summary JSON
 |
 v
Web UI / API / Diff / Remediation
```

## Architecture
LAS is a lightweight Python Web application.

- FastAPI — backend and HTTP API;
- Jinja2 — HTML templates;
- ldap3 — LDAP and Active Directory;
- pywinrm — WinRM;
- WMI — optional Windows management path;
- pywin32 — Windows RPC/NetAPI where available;
- browser-side JavaScript/CSS — interactive UI, filtering, analytics, export, and remediation queue.

Main scan artifacts are file-based and do not require a separate database.

## Requirements

### LAS server
- Python 3.10+;
- DNS resolution for domain names;
- network access to Domain Controllers;
- network access to Windows targets;
- service-account permissions appropriate for the selected collection methods.

Windows is the natural deployment platform for Windows-management-heavy environments. Linux can also host the application when required packages are available and the selected protocols are reachable.

### Active Directory
LDAP access to a DC is required. Global Catalog access is required when GC group expansion is enabled.

### Windows targets
Depending on the selected mode, access may be required to WinRM TCP 5985/5986, SMB/RPC TCP 445 and related RPC ports, WMI/DCOM, and RDP for the corresponding connectivity probe.

## Installation

```bash
git clone https://github.com/aabandre/LAS.git
cd LAS
python -m venv .venv
```

Windows:
```powershell
.\.venv\Scripts\Activate.ps1
```

Linux:
```bash
source .venv/bin/activate
```

Core dependencies:
```bash
pip install fastapi uvicorn ldap3 pywinrm jinja2
```

For WMI/Win32 scenarios:
```bash
pip install WMI pywin32
```

If a deployment-specific dependency file is provided, prefer installing from that file.

## Running the Application

```bash
python app.py
```

Default URLs:
- http://127.0.0.1:8000 — Web UI;
- http://127.0.0.1:8000/summary — Summary.

Network-facing deployment:
```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

For production use, HTTPS, a reverse proxy, IP/ACL restrictions, a dedicated service account, and protected artifact storage are recommended.

## Scan Configuration

### Targeting
Operators can select workstation/server OUs, include/exclude patterns, and operating-system filters.

Examples:
```text
BA-JES-*
SRV-*
*-RDP-*
```

### Performance
Important controls include worker threads, network concurrency, RPC concurrency, probe timeout, host hard timeout, LDAP/GC workers, and group-expansion limits.

For large environments, start with a small OU and gradually increase concurrency while monitoring failures and Domain Controller load.

Stable Fast and Reliable Fast presets are available in the UI.

## Collection Methods

### WinRM
Primary remote PowerShell collection method. It provides structured output and good performance.

Typical errors include WinRM cannot complete the operation, destination cannot be reached, WinRM is not set up to receive requests, Kerberos authentication failed, and Access is denied.

### RPC / SMB
Fallback for local-group collection when WinRM is unavailable and RPC/SMB access is possible.

### WMI
Additional collection path when the required Python module and WMI/DCOM access are available.

## Web UI and Summary

The main page is used to configure and start scans. The operator selects AD parameters, OUs, groups, filters, and performance settings.

Summary is available at /summary and provides total computers, successful/failed checks, risky hosts, local administrators, account distribution, machine details, and Account ↔ Computer heatmap.

### Filtering and pagination
Pagination changes only the visible page. Export uses the complete logical filtered set. For example, if a filter matches 37 administrators and the page size is 25, all 37 are exported.

### Machine details
Machine details can include OS, collection method, processing time, local groups, members, nested groups, and errors.

## Scan Comparison
Two stored scans can be compared to identify new and removed access and changes in risky-machine counts.

Typical cycle:
```text
Scan #1 -> Remediation -> Scan #2 -> Diff
```

## Remediation

### Web UI
The operator selects the account, computers, and local group, adds targets to the remediation queue, reviews them, and confirms the operation.

Backend endpoint:
```text
POST /api/remediate/remove-local-admin
```

### PowerShell export
The generated script:
1. tries WinRM first;
2. falls back to remote ADSI/RPC if WinRM fails;
3. enumerates actual local-group members;
4. removes the matching object;
5. verifies the result;
6. records method and status;
7. writes las-remediation-results.csv.

Statuses:
```text
Removed
AlreadyAbsent
RemovedUnverified
StillPresent
Failed
```

Methods:
```text
WinRM
ADSI-RPC
FAILED
```

Remediation is potentially destructive. Test on a small scope first, verify the account should be removed, keep an alternative administrative path, and retain the original scan.

## Export
Typical artifacts:
```text
results/
├── scan_YYYYMMDD_HHMMSS.json
├── scan_YYYYMMDD_HHMMSS.csv
└── summary_YYYYMMDD_HHMMSS.json
```

JSON is intended for structured machine processing. CSV is convenient for Excel, Power BI, Python, and audit work.

Summary administrator export contains:
```text
account,type,count,via_group,machines
```

The machines column contains all computers in the selected filtered result. A UTF-8 BOM is added so Cyrillic data opens correctly in Microsoft Excel.

## HTTP API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | /scan/start | Start a scan |
| POST | /scan/stop | Stop a scan |
| GET | /scan/status | Status and progress |
| GET | /scan/results | Retrieve results |
| GET | /api/summary | Latest summary |
| GET | /api/scans | List stored scans |
| GET | /api/diff | Compare scans |
| POST | /api/remediate/remove-local-admin | Remove local administrator |
| GET | /download/{file} | Download artifact |

## Logging
The main log is scan.log.

It records scan lifecycle events, LDAP/WinRM/RPC/WMI errors, processing times, and diagnostic messages. A rotating file handler is used.

Enable debug logging temporarily when troubleshooting and return to the normal level afterwards.

## Performance
The main bottlenecks are normally network management protocols, Domain Controllers, DNS and LDAP rather than Python CPU usage.

Recommended approach:
1. test 10–50 machines;
2. review scan.log and Summary;
3. increase concurrency gradually;
4. monitor Domain Controllers.

Do not maximize concurrency solely to minimize scan duration.

## Security
Use a dedicated service account with the minimum required privileges.

Avoid unnecessary Domain Admin usage, hard-coded passwords, credentials in source code, and insecure credential transport.

Restrict network connectivity between LAS and Domain Controllers, Global Catalog, WinRM, SMB/RPC and WMI targets.

Results may contain machine names, domain accounts, group membership, privileged-access relationships, and connection errors. Protect the results directory.

Restrict remediation endpoints to trusted operators.

## Troubleshooting

### WinRM
```powershell
Test-WSMan COMPUTERNAME
winrm quickconfig
```
Check DNS, TCP 5985/5986, Kerberos, SPNs, firewall, WinRM policy, and permissions.

### RPC / SMB
```powershell
Test-NetConnection COMPUTERNAME -Port 445
```
Check SMB, RPC Endpoint Mapper, firewall, required services, and permissions.

### LDAP
Check DC DNS, TCP 389/636, TCP 3268/3269 for Global Catalog, bind credentials, LDAP filters, and DC availability.

### Corrupted Cyrillic
LAS contains handling for common Windows/PowerShell encoding problems and structured UTF-8 output. Check code page, locale, and PowerShell output encoding when troubleshooting.

### Unreachable computer
An unreachable computer must not automatically be considered clean. Check DNS, routing, SMB, WinRM, RPC, credentials, firewall, and scan.log.

## Project Structure

```text
LAS/
├── app.py
├── templates/
│ ├── index.html
│ └── summary.html
├── docs/
│ ├── UI_OPERATOR_GUIDE_RU.md
│ └── CONFLUENCE_UI_GUIDE_RU.md
├── results/
├── scan.log
├── README.md
└── README_EN.md
```

app.py contains the backend, scan engine, LDAP, WinRM, RPC/WMI, API, persistence, and remediation.

templates contains the Web UI, Summary, filters, export, diff, and remediation queue.

docs contains operator and internal knowledge-base documentation.

## Recommended Operating Workflow

```text
1. Scan
 ↓
2. Summary
 ↓
3. Risk analysis
 ↓
4. Identify unwanted access
 ↓
5. Remediation
 ↓
6. New scan
 ↓
7. Diff
 ↓
8. Report
```

This produces a measurable before/after remediation workflow.

## Limitations
LAS does not replace PAM, SIEM, EDR, Microsoft Defender for Identity, Group Policy, or CMDB platforms.

Its purpose is the inventory, analysis, comparison, and controlled remediation of local Windows privileged access.

## Documentation
- docs/UI_OPERATOR_GUIDE_RU.md — Russian operator guide;
- docs/CONFLUENCE_UI_GUIDE_RU.md — Confluence-ready Russian guide;
- README.md — Russian project documentation;
- README_EN.md — English project documentation.

## Repository
https://github.com/aabandre/LAS

## License
If the repository does not contain a separate license file, terms of use are determined by the project owner.