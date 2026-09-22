# Azure Honeypot: Live Cyber Attack Detection & Visualization

A hands-on home lab where I deployed a deliberately vulnerable Windows VM to the public internet, captured real attacker login attempts, ingested and enriched the logs in Microsoft Sentinel, and built a live world map of attack origins.

<img width="1919" height="800" alt="image" src="https://github.com/user-attachments/assets/6df2776d-c0b5-4943-936c-e43fc17366a1" />




## Overview

This project simulates a real-world Security Operations Center (SOC) workflow:

1. Stand up an intentionally exposed "honeypot" VM in the cloud
2. Let it get attacked by real bots/scanners on the internet
3. Collect and centralize the resulting security logs
4. Enrich raw IP addresses with geographic data
5. Visualize the attacks in real time on a world map

The goal was to build practical experience with SIEM tooling, log analysis, and KQL core skills for a SOC analyst or security engineer role.

## Architecture

```
Attacker (Internet)
        │
        ▼
Windows 10 VM (Azure) ── Firewall disabled, all inbound traffic allowed
        │
        ▼
Windows Event Logs (Security log, Event ID 4625 = failed logon)
        │
        ▼
Azure Monitor Agent (AMA) + Data Collection Rule (DCR)
        │
        ▼
Log Analytics Workspace (LAW)
        │
        ▼
Microsoft Sentinel (SIEM)
        │
        ├── GeoIP Watchlist (IP → location enrichment)
        │
        ▼
Sentinel Workbook (Attack Map Visualization)
```

## Tools & Technologies

- **Microsoft Azure** – Virtual Machines, Networking, Log Analytics
- **Microsoft Sentinel** – Cloud-native SIEM
- **KQL (Kusto Query Language)** – Log querying and analysis
- **Windows Event Viewer** – Local log inspection
- **Sentinel Watchlists** – GeoIP enrichment
- **Sentinel Workbooks** – Custom data visualization (JSON-based)

## Build Steps

### 1. Provisioned the environment
Created an Azure subscription and deployed a Windows 10 VM to act as the target.

### 2. Exposed the honeypot
- Configured the Network Security Group (NSG) to allow **all inbound traffic**
- Disabled the Windows Firewall entirely (`wf.msc`)
- This intentionally insecure configuration invites internet-wide scanning and brute-force attempts

### 3. Verified logging locally
Simulated failed logins and confirmed they appeared in Event Viewer under **Event ID 4625** (failed logon) before scaling up log collection.

### 4. Centralized logs
- Created a **Log Analytics Workspace (LAW)**
- Deployed a **Microsoft Sentinel** instance connected to the LAW
- Configured the **Windows Security Events via AMA** connector and a **Data Collection Rule (DCR)** to stream VM security logs into Sentinel

### 5. Queried real attack data with KQL
```kql
SecurityEvent
| where EventID == 4625
```
Within hours of exposing the VM, real failed login attempts from around the world started appearing in the logs.

### 6. Enriched logs with geographic data
Raw logs only contain IP addresses — no location info. I imported a public GeoIP CSV as a **Sentinel Watchlist** (~54,000 IP ranges) and joined it against the security logs:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
```

### 7. Built a live attack map
Created a Sentinel Workbook and used a custom JSON query (`map.json` in this repo) to render a real-time world map, plotting each failed login attempt by geographic origin.

## Results / Findings

- Captured hundreds of real, unsolicited login attempts within the first 24 hours of exposure
- Identified the top countries/regions generating brute-force traffic
- Confirmed that unprotected RDP/VMs on the public internet are attacked almost immediately no active "targeting" required, just automated internet-wide scanning



## Repo Contents

| File | Description |
|---|---|
| `map.json` | Sentinel Workbook JSON used to build the attack map |
| `queries.kql` | KQL queries used for log analysis and GeoIP enrichment |
| `screenshots/` | Event Viewer, Sentinel architecture, and attack map screenshots |

## Skills Demonstrated

- Cloud infrastructure setup (Azure)
- SIEM configuration and log ingestion pipelines
- KQL log querying and analysis
- Data enrichment techniques
- Security data visualization
- Understanding of common attack patterns (brute-force / credential access)

## Resources Used

- [GeoIP dataset](https://github.com/joshmadakor1/lognpacific-public) for IP-to-location enrichment
- [KC7 Cyber](https://kc7cyber.com/) – free KQL practice

---

*This lab was built for educational purposes to develop hands-on SOC analyst skills.*
