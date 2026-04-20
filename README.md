# Zero-Trust OT Security Lab

A containerised laboratory for validating **Zero-Trust Architecture (ZTA)** in Operational Technology networks. The environment reproduces a chemical reactor process — PLC, HMI, Engineering Workstation — segmented across five Purdue-model zones and protected by identity-aware proxying, deep packet inspection, and centralised SIEM correlation.

Built as the empirical validation platform for academic research on *Zero-Trust Architectures in Critical Infrastructure*.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Network Segmentation](#network-segmentation)
- [Security Components](#security-components)
- [Firewall Policy Matrix](#firewall-policy-matrix)
- [IDS Rules & Anomaly Detection](#ids-rules--anomaly-detection)
- [Attack Scenarios](#attack-scenarios)
- [Dissertation Metrics Engine](#dissertation-metrics-engine)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Author](#author)

---

## Architecture Overview

The lab models a five-zone OT network based on the Purdue Enterprise Reference Architecture (PERA). Unlike traditional perimeter-based designs that implicitly trust internal traffic, this environment enforces **continuous identity verification** at every boundary crossing. No service communicates directly with another unless explicitly authorised through a combination of identity, group membership, source IP, and protocol constraints.

All services run as Docker containers interconnected via isolated **MacVLAN** networks (one per Purdue zone). A centralised router enforces iptables-based micro-segmentation with a **default-deny** forwarding policy, while an identity-aware reverse proxy (Pomerium) gates all human access through Keycloak-authenticated sessions with MFA.

### Container Inventory

| Container | Role | Zone | IP Address |
| :--- | :--- | :--- | :--- |
| `simulation` | Physical process simulator (reactor) | Control (L1) | `192.168.95.10` |
| `plc` | OpenPLC — runs the control logic (`chemical.st`) | Control (L1) | `192.168.95.2` |
| `HMI` | ScadaBR — supervisory dashboard | Supervisory (L2) | `192.168.96.10` |
| `EWS` | Engineering Workstation — PLC programming | Operations (L3) | `192.168.97.5` |
| `pomerium` | Identity-Aware Proxy (IAP) | IDMZ (L3.5) | `192.168.90.21` |
| `guacamole` | Remote desktop gateway | IDMZ (L3.5) | `192.168.90.22` |
| `guacd` | Guacamole connection daemon | IDMZ (L3.5) | `192.168.90.23` |
| `guacamole_db` | PostgreSQL for Guacamole | IDMZ (L3.5) | `192.168.90.24` |
| `keycloak` | Identity Provider (IdP) with MFA | Enterprise (L4) | `192.168.100.20` |
| `wazuh.manager` | SIEM manager — log collection & correlation | Enterprise (L4) | `192.168.100.51` |
| `wazuh.indexer` | OpenSearch indexer | Enterprise (L4) | `192.168.100.52` |
| `wazuh.dashboard` | SIEM dashboard | Enterprise (L4) | `192.168.100.50` |
| `router` | Central firewall, IDS (Suricata), routing | All zones | Multi-homed |
| `kali` | Attacker machine for red-team scenarios | Enterprise (L4) | `192.168.100.100` |

---

## Network Segmentation

Each zone maps to a dedicated MacVLAN network backed by VLAN-tagged host interfaces:

| Purdue Level | Zone Name | Subnet | VLAN | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| Level 0/1 | Control | `192.168.95.0/24` | 95 | PLC and physical process |
| Level 2 | Supervisory | `192.168.96.0/24` | 96 | HMI — process monitoring |
| Level 3 | Operations | `192.168.97.0/24` | 97 | Engineering workstation |
| Level 3.5 | IDMZ | `192.168.90.0/24` | 90 | Proxies and remote access |
| Level 4 | Enterprise | `192.168.100.0/24` | 100 | Identity, SIEM, attacker |

An additional **bridge** network (`a-grfics-admin`) carries internal DNS resolution between containers that need to reach `keycloak.localhost.pomerium.io` without traversing the firewall.

---

## Security Components

### Pomerium — Identity-Aware Proxy
Every web interface (HMI, PLC console, Guacamole, Simulation dashboard, Router admin) is published exclusively through Pomerium. Access requires:
- Authentication via Keycloak OpenID Connect.
- Membership in the appropriate group (`ot-engineer`, `plc-developer`, or `admin`).
- For PLC management: **source IP restriction** to the EWS (`192.168.97.5/32`).

### Keycloak — Identity Provider
Centralised SSO with **Multi-Factor Authentication** (TOTP) enforced for the `engineer` user. User groups (`ot-engineer`, `plc-developer`, `admin`) map directly to Pomerium access policies.

### Suricata — Intrusion Detection System
Runs inline on the router, inspecting all inter-zone traffic with custom OT-specific rules (see [IDS Rules](#ids-rules--anomaly-detection)).

### Wazuh — SIEM / XDR Platform
Three-container deployment (Manager, Indexer, Dashboard) that ingests:
- **Suricata** alerts (via Filebeat).
- **Keycloak** authentication events (login success/failure).
- **Netfilter** firewall drop logs (`NFLOG`).
- **Wazuh agents** on the EWS, Router, and HMI (File Integrity Monitoring, syscheck).
- **Guacamole** session audit logs (via syslog).

Custom correlation rules detect multi-step kill chains (e.g., file tampering followed by PLC login within 10 minutes triggers an Insider Threat alert).

### Guacamole — Remote Access Gateway
Provides browser-based VNC/RDP/SSH access to the EWS through the IDMZ. All sessions are recorded and stored for forensic audit.

---

## Firewall Policy Matrix

The router enforces a **default-deny** forwarding policy. All traffic not matching an explicit rule is logged via `NFLOG` and dropped. The permitted flows are:

| # | Source | Destination | Proto | Port | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Supervisory zone (`192.168.96.0/24`) | Wazuh Manager | TCP | 1514 | Agent registration & log shipping |
| 2 | Operations zone (`192.168.97.0/24`) | Wazuh Manager | TCP | 1514 | Agent registration & log shipping |
| 3 | IDMZ zone (`192.168.90.0/24`) | Wazuh Manager | TCP | 1514 | Agent registration & log shipping |
| 4 | Supervisory zone (`192.168.96.0/24`) | Wazuh Manager | TCP | 1515 | Agent key exchange |
| 5 | Operations zone (`192.168.97.0/24`) | Wazuh Manager | TCP | 1515 | Agent key exchange |
| 6 | IDMZ zone (`192.168.90.0/24`) | Wazuh Manager | TCP | 1515 | Agent key exchange |
| 7 | HMI (`192.168.96.10`) | PLC (`192.168.95.2`) | TCP | 502 | Modbus/TCP — process control |
| 8 | Pomerium (`192.168.90.21`) | HMI (`192.168.96.10`) | TCP | 8080 | Proxied HMI web access |
| 9 | Pomerium (`192.168.90.21`) | PLC (`192.168.95.2`) | TCP | 8080 | Proxied PLC management console |
| 10 | Pomerium (`192.168.90.21`) | Keycloak (`192.168.100.20`) | TCP | 8080 | IdP token exchange |
| 11 | Pomerium (`192.168.90.21`) | Simulation (`192.168.95.10`) | TCP | 80 | Proxied simulation dashboard |
| 12 | Pomerium (`192.168.90.21`) | Guacamole (`192.168.90.22`) | TCP | 8080 | Proxied remote access gateway |
| 13 | Guacamole (`192.168.90.22`) | Guacd (`192.168.90.23`) | TCP | 4822 | Guacamole daemon protocol |
| 14 | Guacamole (`192.168.90.22`) | Guac DB (`192.168.90.24`) | TCP | 5432 | PostgreSQL connection |
| 15 | EWS (`192.168.97.5`) | Pomerium (`192.168.90.21`) | TCP | 443 | Engineer → proxy access |
| 16 | EWS (`192.168.97.5`) | Keycloak (`192.168.100.20`) | TCP | 8080 | Engineer authentication |
| 17 | Guacd (`192.168.90.23`) | EWS (`192.168.97.5`) | TCP | 5900 | VNC remote desktop |
| 18 | Guacd (`192.168.90.23`) | EWS (`192.168.97.5`) | TCP | 22 | SSH access |
| 19 | Guacd (`192.168.90.23`) | EWS (`192.168.97.5`) | TCP | 3389 | RDP access |
| 20 | Guacamole (`192.168.90.22`) | Wazuh Manager | UDP | 514 | Syslog audit export |
| **∗** | **Everything else** | **Everything else** | **—** | **—** | **LOGGED & DROPPED** |

---

## IDS Rules & Anomaly Detection

Custom Suricata signatures in `router/ot.rules` provide OT-specific threat detection:

| SID | Severity | Description | Trigger |
| :--- | :--- | :--- | :--- |
| `1000020` | High | Reactor Pressure > 90% | Modbus response byte value > 58981 |
| `1000021` | Critical | Reactor Pressure > 97% (explosion risk) | Modbus response byte value > 63568 |
| `1000030` | High | Unauthorised Modbus Write attempt | Write from any source ≠ HMI |
| `1000031` | Medium | Unauthorised Modbus Read (recon) | Read from Enterprise zone |
| `1000041` | Medium | Network scan / Nmap probes | SYN packets from Enterprise to OT zones |
| `1000100` | — | PLC login attempt (internal) | HTTP POST to `/login` on PLC |
| `1000101` | High | PLC login successful | HTTP redirect to `/dashboard` from PLC |

> **Tuning note:** The pressure threshold was raised from 80% to 90% to prevent false positives during normal operation (baseline ~84%). This ensures that alerts fire only during genuine process manipulation.

---

## Attack Scenarios

The lab includes an automated attack suite (`attacker/attack_automation.sh`) that validates the detection capabilities of the security stack against three threat profiles:

### Scenario A — OT Network Reconnaissance
An attacker on the Enterprise network performs Nmap scanning and Modbus register reads against OT assets. The firewall blocks cross-zone access and logs every attempt; Suricata flags protocol-layer discovery.

### Scenario B — Insider Threat: Reactor Sabotage
A compromised engineer uses legitimate credentials to:
1. Authenticate through Pomerium and open a Guacamole VNC session to the EWS.
2. Modify the PLC program (`chemical.st`) on the EWS filesystem.
3. Upload the tampered program to the PLC via its web management console.

The SIEM correlates **File Integrity Monitoring** changes with **PLC console access** to produce an Insider Threat alert before reactor pressure reaches critical levels.

### Scenario C — Identity Brute Force & MFA Validation
An attacker attempts credential stuffing (8 wrong passwords), then uses the **correct password without OTP**, then guesses wrong OTP codes. All attempts fail — MFA enforcement blocks token issuance even with valid credentials.

---

## Dissertation Metrics Engine

The Python-based evaluation engine (`calculate_dissertation_metrics.py`) quantifies the security posture with:

| Metric | Formula | Description |
| :--- | :--- | :--- |
| **Visibility Coverage** | Detected Steps / Total Steps × 100 | Percentage of kill-chain steps that generated at least one SIEM alert |
| **Mean Time to Detect** | Σ(T_detect − T_attack) / N | Average latency between attack execution and SOC alerting |
| **True Positives** | Alerts within [−60s, +300s] of attack steps | Security events correlated to known attack activity |
| **False Positives** | Alerts outside valid attack windows | Noise or alarm fatigue from non-attack periods |
| **Detection Precision** | TP / (TP + FP) | Specificity of correlation rules |

A configurable **Test Horizon** boundary discards all historical alerts before the test window to prevent residual noise from skewing live metrics.

### Running the Evaluation
```bash
# 1. Execute all attack scenarios
./attacker/attack_automation.sh

# 2. Generate the metrics report
python3 calculate_dissertation_metrics.py --horizon 10
```

---

## Getting Started

### Prerequisites
- Docker Engine & Docker Compose v2
- Python 3.10+ (for metrics engine)
- VLAN-capable host network interface
- At least 16 GB RAM recommended

### Quick Start
```bash
# Clone the repository
git clone https://github.com/<your-org>/Zero-Trust-OT-lab.git
cd Zero-Trust-OT-lab

# Run the automated setup
chmod +x setup_lab.sh
./setup_lab.sh
```

The setup script will:
1. Detect your host network interface for MacVLAN mapping.
2. Export and back up the current Keycloak realm to `./keycloak_backups/`.
3. Generate SSL certificates for the Wazuh stack (first run only).
4. Build all custom container images from source.
5. Start the full environment with `docker compose up -d`.

### Accessing the Lab

| Interface | URL | Required Group |
| :--- | :--- | :--- |
| HMI Dashboard | `https://hmi.localhost.pomerium.io` | `ot-engineer` |
| PLC Management | `https://plc.localhost.pomerium.io` | `ot-engineer` + source IP |
| Remote Desktop | `https://guacamole.localhost.pomerium.io` | `ot-engineer` |
| Simulation View | `https://simulation.localhost.pomerium.io` | `ot-engineer` |
| Router / Firewall | `https://router.localhost.pomerium.io` | `admin` |
| SIEM Dashboard | `https://localhost:5601` | Direct (admin/admin) |

> **Note:** Ensure your `/etc/hosts` resolves `*.localhost.pomerium.io` to `127.0.0.1`, or configure a local DNS wildcard.

---

## Project Structure

```
Zero-Trust-OT-lab/
├── attacker/                  # Kali container: attack scripts & automation
│   ├── attack_automation.sh   # Orchestrates Scenarios A, B, C
│   ├── attack_suite.py        # Modbus scanning tool
│   └── scenario_b_host.sh     # Insider threat kill-chain
├── guacamole/                 # Guacamole config, extensions, DB init
├── keycloak_backups/          # Timestamped realm exports
├── plc/                       # OpenPLC build context
├── pomerium/
│   └── config.yaml            # Route definitions & access policies
├── router/
│   ├── setup-firewall.sh      # iptables rules (default-deny)
│   └── ot.rules               # Custom Suricata IDS signatures
├── scadalts/                  # ScadaBR (HMI) build context
├── simulation/                # Reactor simulation build context
├── wazuh_config/
│   ├── rules.xml              # Custom SIEM correlation rules
│   ├── decoders.xml           # Custom log decoders
│   └── wazuh_indexer_ssl_certs/
├── workstation/               # EWS build context
├── calculate_dissertation_metrics.py
├── docker-compose.yml
├── setup_lab.sh               # One-touch deployment script
└── .env                       # Secrets (not committed)
```

---

## Author

**Tryfon Iason Papatriantafyllou**
Version: 1.0
