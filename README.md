# Azure Honeypot & SOC Lab: Tracking Live RDP Brute-Force Attacks with Microsoft Sentinel

<img width="1919" height="806" alt="image" src="https://github.com/user-attachments/assets/9dd9e617-9431-4120-8b6c-7eec416f51e4" />
![Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-blue)
![KQL](https://img.shields.io/badge/KQL-Log%20Analytics-orange)
![Windows 11](https://img.shields.io/badge/Windows%2011-Honeypot-0078D6?logo=windows&logoColor=white)

## Summary

I wanted to see what actually happens when a Windows machine is left exposed on the public internet, and to practice the workflow a SOC analyst uses to detect, investigate, and visualize that activity. To do that, I built a honeypot in Microsoft Azure, piped its security logs into Microsoft Sentinel, enriched the attacker IPs with geolocation data, and built a live attack map.

**Result:** my honeypot logged **more than 161,000 failed logon attempts** from attackers across six continents, with a single IP in Poland hitting the machine every one to three minutes.

## What I Set Out to Answer

1. How quickly does an exposed machine get discovered and attacked?
2. Where are the attacks coming from, and how are they distributed?
3. What accounts are attackers trying to break into?
4. How would I detect and respond to this in a real SOC?

## Tools & Technologies

| Category | Tools |
|---|---|
| Cloud platform | Microsoft Azure (Azure for Students subscription) |
| SIEM | Microsoft Sentinel |
| Log storage / analytics | Log Analytics Workspace, KQL |
| Log collection | Azure Monitor Agent, Data Collection Rule |
| Honeypot | Windows 11 Pro VM (Standard B2as v2) |
| Networking | Virtual Network, Subnet, Network Security Group, Public IP |
| Enrichment | GeoIP watchlist (~54,800 IPv4 ranges) |

## Architecture

```
            Internet (attackers / bots)
                       │  RDP brute force
                       ▼
        ┌──────────────────────────────────┐
        │  Public IP  (MOTSUCORT-NET-NCUS-1-ip)
        │  NSG: all inbound allowed         │
        │  ┌────────────────────────────┐  │
        │  │ Windows 11 VM (honeypot)   │  │
        │  │ MOTSUCORT-NET-NCUS-1       │  │
        │  │ Host firewall disabled     │  │
        │  └─────────────┬──────────────┘  │
        │  VNet: MOTSUVENT-SOC-LAB 10.0.0.0/16
        └────────────────┼─────────────────┘
                         │ Azure Monitor Agent (Security Events)
                         ▼
             Log Analytics Workspace (LAWMO-SOC-LAB-004)
                         │
                         ▼
               Microsoft Sentinel (SIEM)
          GeoIP watchlist ─► KQL enrichment ─► Attack Map workbook
```

## Environment

| Resource | Name | Details |
|---|---|---|
| Virtual machine | `MOTSUCORT-NET-NCUS-1` | Windows 11 Pro, 2 vCPU / 8 GiB, North Central US |
| Virtual network | `MOTSUVENT-SOC-LAB` | 10.0.0.0/16, 2 subnets |
| Network security group | `MOTSUCORT-NET-NCUS-1-nsg` | Inbound open to all traffic |
| Public IP | `MOTSUCORT-NET-NCUS-1-ip` | Standard SKU, regional |
| Log Analytics workspace | `LAWMO-SOC-LAB-004` | Connected to Microsoft Sentinel |
| Watchlist | `geoip` | Search key: `network` |

I picked a small B2as v2 VM to keep costs low on my student credit, and used Windows 11 because RDP on Windows is one of the most heavily targeted services on the internet, which meant I would collect meaningful data quickly.

---

## How I Built It

### 1. Deployed the honeypot VM

I deployed a Windows 11 Pro VM in North Central US with a private IP of `10.0.1.4` and a public IP so it could be reached from the internet.

![Honeypot VM overview](images/01-honeypot-vm-overview.png)

### 2. Set up the virtual network

The VM lives in the `MOTSUVENT-SOC-LAB` virtual network. I deliberately left DDoS protection, Azure Firewall, peerings, and private endpoints off so nothing would filter traffic before it reached the honeypot.

![Virtual network](images/02-virtual-network.png)

### 3. Opened the VM to the internet

I made the VM as exposed as possible by allowing all inbound traffic on the Network Security Group and turning off Windows Defender Firewall inside the VM. The Standard public IP below is the address attackers found and targeted.

![Public IP resource](images/03-public-ip.png)

> This setup is intentionally insecure. I ran it in an isolated lab subscription with nothing of value on the machine.

### 4. Forwarded logs to Log Analytics and Sentinel

I created the `LAWMO-SOC-LAB-004` Log Analytics workspace, enabled Microsoft Sentinel on it, and installed the Windows Security Events data connector. A Data Collection Rule scoped to the honeypot sends its Windows Security log into the workspace.

### 5. Confirmed the attacks with Event ID 4625

Event ID **4625** is logged every time an account fails to sign in. My first query confirmed that brute-force traffic was already flowing in:

```kql
SecurityEvent
| where EventID == 4625
```

![Failed logons 4625](images/04-failed-logons-4625.png)

### 6. Added geolocation with a watchlist

Raw security events only include the attacker's IP address. I uploaded a GeoIP dataset ([`data/geoip-summarized.csv`](data/geoip-summarized.csv)) as a Sentinel watchlist named `geoip` with `network` as the search key, then used `ipv4_lookup` to match each IP to its network range. Here I focused on one of the most persistent attackers:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "77.83.38.24"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress,
    cityname, countryname, latitude, longitude
```

![GeoIP enriched query](images/05-geoip-enriched-query.png)

### 7. Built the attack map

I created a Sentinel workbook with a map visualization ([`queries/attack-map-workbook.json`](queries/attack-map-workbook.json)). It aggregates 30 days of failed logons by IP and location, sizes each bubble by failure count, and colors it on a green-to-red heatmap.

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude,
    city = cityname, country = countryname,
    friendly_location = strcat(cityname, " (", countryname, ")");
```

![Sentinel overview](images/06-sentinel-overview.png)

---

## Findings

![Windows VM Attack Map](images/07-attack-map.png)

| Rank | Location | Failed logons | Share |
|---|---|---|---|
| 1 | Paris, France | 15.3K | 9.5% |
| 2 | Jarocin, Poland | 14.5K | 9.0% |
| 3 | Stockholm, Sweden | 14.5K | 9.0% |
| 4 | Springfield, United States | 11.1K | 6.9% |
| 5 | Hollywood, United States | 9.42K | 5.8% |
| 6 | Indianapolis, United States | 9.3K | 5.8% |
| 7 | Prague, Czechia | 7.74K | 4.8% |
| 8 | Kelliher, Canada | 6.43K | 4.0% |
| 9 | Jakarta, Indonesia | 5.56K | 3.4% |
| – | All other locations | 67.5K | 41.8% |
| | **Total** | **~161K** | |

*The workbook caps the map at 100 rows, so the real total is likely higher.*

### My analysis

**Europe was the biggest source.** Paris, Jarocin, Stockholm, and Prague alone produced about 52K attempts, roughly a third of everything recorded. The three U.S. cities in the top ten added about 30K more.

**A handful of IPs did a lot of the work.** The top three locations accounted for over a quarter of all attempts. When I drilled into `77.83.38.24` (Jarocin, Poland), it was retrying every one to three minutes around the clock, a pattern that points to an automated tool rather than a person.

**The long tail is huge.** Almost 42% of attempts came from locations outside the top nine, spread across South America, Africa, Asia, and Australia. Blocking a few countries would not have stopped most of this.

**Attackers guessed default and localized admin names.** The usernames I saw included `admin`, `administrator`, `adminuser`, and `STUDENT`, plus `Administrador` (Spanish/Portuguese) and `АДМИНИСТРАТОР` (Russian). Several attempts arrived within the same second, which is consistent with wordlist-driven brute forcing that targets built-in accounts across different Windows language versions.

**Location ≠ attacker.** These coordinates show where the IP is registered, which is often a VPS or hosting provider. The real operator could be anywhere.

### MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Repeated 4625 events against the same accounts from single IPs |
| Brute Force: Password Spraying | T1110.003 | Many common account names attempted from the same source |
| External Remote Services | T1133 | Attacks targeting the internet-exposed RDP service |

## Detection & Response Ideas

If this were a production environment, these are the next steps I'd take.

**Alert on high-volume sources.** A scheduled analytics rule could flag any IP that fails logon repeatedly:

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count(),
            AccountsTried = dcount(TargetUserName),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated) by IpAddress
| where Attempts > 50
| order by Attempts desc
```

**Watch for a success after failures.** The most important alert is a 4624 (successful logon) from an IP that previously generated many 4625s, since that would indicate a compromised account.

**Harden the host.** Remove public RDP, use Azure Bastion or Just-In-Time VM access, rename or disable the built-in Administrator account, and enforce an account lockout policy.

**Automate containment.** A Sentinel playbook could add offending IPs to an NSG deny rule automatically.

## Skills Demonstrated

- Azure infrastructure deployment (VMs, VNets, NSGs, public IPs)
- SIEM setup and data connector configuration
- Log collection with Azure Monitor Agent and Data Collection Rules
- KQL for filtering, enrichment, and aggregation
- Threat data enrichment with watchlists
- Security visualization with Sentinel Workbooks
- Attack pattern analysis and MITRE ATT&CK mapping

## Cleanup

When I finished, I deleted the lab resource groups so the honeypot would stop running and stop using my Azure for Students credit.

## Repository Structure

```
.
├── README.md
├── data/
│   └── geoip-summarized.csv          # GeoIP watchlist data
├── queries/
│   └── attack-map-workbook.json      # Sentinel workbook map element
└── images/                           # Lab screenshots
```
