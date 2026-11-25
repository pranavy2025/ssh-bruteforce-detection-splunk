# SSH Brute-Force Detection with Splunk SIEM

## Project Overview
Built an end-to-end SSH brute-force detection lab simulating real-world credential attacks and detecting them using Splunk SIEM. This project replicates a core SOC analyst workflow: understanding attacker behavior, ingesting logs, writing detection logic, and building alerting infrastructure.

## Lab Architecture
| Machine | Role | OS | IP |
|---|---|---|---|
| Kali Linux | Attacker | Kali 2026.2 | 192.168.56.102 |
| Ubuntu Server | Victim + SIEM | Ubuntu 22.04 LTS | 192.168.56.101 |

Both VMs connected via VirtualBox Host-only network (isolated, no internet exposure).

## Tools Used
- **Nmap** — reconnaissance, port scanning
- **Hydra** — SSH brute-force credential attack
- **Metasploit** — auxiliary SSH login scanner
- **Splunk Enterprise** — SIEM, log ingestion, SPL queries, dashboarding, alerting

## Attack Simulation
### 1. Nmap Reconnaissance
```bash
nmap -sV 192.168.56.101
```
Confirmed port 22 (OpenSSH 8.9p1) open on victim.

### 2. Hydra Brute-Force
```bash
hydra -L users.txt -P passwords.txt ssh://192.168.56.101
```
Generated 78 failed login attempts across 3 attack bursts, with successful credential discovery.

## Detection Logic (SPL Queries)

### Query 1 — All Failed Logins
index=main sourcetype=linux_secure "Failed password"

Baseline filter to isolate all failed SSH authentication events from auth.log.

### Query 2 — Top Attacking IPs

index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<attempted_user>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts by src_ip
| sort -failed_attempts

Extracts source IP and username from each event using regex, then ranks IPs by total failed attempts. 192.168.56.102 generated 78 failures.

### Query 3 — Threshold Detection
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<attempted_user>\S+) from (?<src_ip>\S+)"
| bin _time span=5m
| stats count as failed_attempts by src_ip, _time
| where failed_attempts >= 5

Groups events into 5-minute windows and surfaces any IP exceeding 5 failures — the core brute-force detection rule. Detected two breaching windows (17 and 61 attempts).

### Query 4 — Compromise Indicators
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "(Failed|Accepted) password for (invalid user )?(?<attempted_user>\S+) from (?<src_ip>\S+)"
| transaction src_ip startswith="Failed password" endswith="Accepted password" maxspan=10m
| table _time src_ip attempted_user duration eventcount

Identifies sessions where an attacker transitioned from failed attempts to a successful login within 10 minutes — the highest-priority compromise indicator. Detected 6 such transactions.

## Dashboard
Built a 4-panel Splunk dashboard titled "SSH Brute Force Detection":
- **Failed Logins Over Time** — timechart showing 3 attack bursts
- **Top Attacking IPs** — bar chart ranking source IPs by failure count
- **Threshold Breaches** — table of 5-minute windows exceeding threshold
- **Compromise Indicators** — table of failure-to-success transitions

## Alerting
Configured a scheduled Splunk alert using cron schedule `*/5 * * * *` that triggers when any result exceeds the threshold (number of results > 0). Alert fired automatically during testing at 2026-11-25 06:45:01 UTC confirming end-to-end detection pipeline.

## Key Takeaways
- Password-based SSH authentication is highly vulnerable to automated brute-force attacks
- Log normalization via regex extraction (rex) is foundational to all SIEM detection work
- Threshold-based alerting requires tuning to balance detection sensitivity and false positive rate
- The most dangerous indicator is not raw failure count but failures followed by a successful login — this signals a completed compromise
- Running Splunk on the same host as the victim demonstrates a local log forwarding architecture common in smaller enterprise environments
