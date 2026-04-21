# Zero-Trust OT Security Lab

A containerized laboratory for empirically validating **Zero-Trust Architecture (ZTA)** defensive controls against realistic OT attack scenarios. The environment reproduces a chemical reactor process across five Purdue Enterprise Reference Architecture zones, with identity-aware proxying, firewall-based micro-segmentation, deep packet inspection (IDS), and centralized SIEM correlation.

## What Makes This Lab Unique

- **OT-Specific Threat Scenarios** — Modbus protocol reconnaissance, false data injection, and insider-threat sabotage (not generic IT attacks)
- **Automated Attack Playbooks** — Playwright-driven scenario automation for reproducible, timing-precise threat emulation
- **Quantitative Security Metrics** — Measures detection coverage, mean-time-to-detect (MTTD), precision, and sensitivity across kill chains
- **Multi-Layer Defense Validation** — Zero-trust enforcement at identity, network, and protocol layers simultaneously
- **Educational & Research-Grade** — Containerized for portability; suitable for academic validation, red-team training, and ZTA architecture research

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
| `HMI` | ScadaLTS — supervisory dashboard | Supervisory (L2) | `192.168.96.10` |
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

The lab includes a fully automated attack suite (`attack_logic/attack_automation.sh`) that validates the security stack's detection capabilities against three threat profiles. Each scenario can be run in isolation or as part of the complete evaluation.

### Scenario A — OT Network Reconnaissance
**Attack Profile:** Remote attacker from Enterprise zone.

An attacker on the Enterprise network performs:
- Nmap scanning across zones (network discovery)
- Modbus register reads (protocol reconnaissance)
- **Unauthorized Modbus Write (False Data Injection)** against the reactor

**Defense Response:** The router's default-deny policy blocks all cross-zone access. Suricata detects protocol-layer scanning and write attempts; Wazuh logs all dropped packets via NFLOG and correlates with IDS alerts.

### Scenario B — Insider Threat: Automated Reactor Sabotage
**Attack Profile:** Compromised engineer with valid credentials.

A Playwright-automated attack chain:
1. **Authentication** — Logs in to Pomerium using valid engineer credentials.
2. **Remote Access** — Establishes a Guacamole VNC session to the EWS desktop.
3. **Program Tampering** — Modifies the reactor control logic (`chemical.st`) via direct filesystem editing.
4. **Malicious Deployment** — Uploads the tampered PLC program through the legitimate web management interface.
5. **Process Manipulation** — Triggers high reactor pressure (>90%) to demonstrate control-flow hijacking.

**Detection Mechanism:** Wazuh correlates:
- **File Integrity Monitoring** — detects changes to `chemical.st` on the EWS
- **PLC Access Logs** — HTTP POST to `/login` + `/upload` endpoints
- **Pressure Anomaly** — Suricata detects Modbus response values exceeding baseline

A multi-step correlation rule fires an **Insider Threat** alert within seconds of the sabotage.

**Implementation:** Automated via Playwright (`attack_logic/tools/playwright_guacamole.py`), eliminating manual GUI testing while maintaining full fidelity of human interaction patterns.

### Scenario C — Identity Brute Force & Multi-Factor Authentication Validation
**Attack Profile:** Remote attacker targeting credential compromise.

An attacker attempts:
1. **Credential Stuffing** — Eight consecutive failed password attempts
2. **Bypass Valid Credentials** — Submits correct password without OTP
3. **OTP Brute Force** — Guesses random 6-digit codes

**Defense Response:** Keycloak's MFA enforcement rejects all attempts—even correct credentials without a valid OTP are denied. SIEM detects and alerts on failed authentication patterns; subsequent account lockout is enforced after threshold violation.

---

## Dissertation Evaluation Results 

### Latest Test Run Summary

Completed **10 consecutive evaluations** of the Zero-Trust OT security lab against three attack scenarios. All tests achieved **100% visibility coverage** across 15 kill-chain steps:

#### Overall Metrics (10-Run Average)
- **Visibility Coverage**: 100.0% (15/15 attack steps detected across all runs)
- **Mean Time to Detect (MTTD)**: ~15.8 seconds average response time
- **True Positives (TP)**: 22 per run (consistent detection)
- **False Positives (FP)**: 14-15 per run (low false-alarm rate)
- **Detection Precision**: 59.5-61.1% (alert specificity to actual attacks)

#### Per-Scenario Performance
- **Scenario A** (Reconnaissance): 100% coverage, ~0.7s MTTD
- **Scenario B** (Insider Threat): 100% coverage, ~38.5s MTTD
- **Scenario C** (Credential Brute Force): 100% coverage, ~0.6s MTTD

#### Key Findings
1. **Network segmentation is effective** — All external reconnaissance attempts detected at zero latency
2. **Insider threats require patience** — File modification detections depend on agent polling intervals (~38s in Scenario B)
3. **Identity enforcement is crisp** — MFA and brute-force detection fires immediately (<1s)
4. **Wazuh/Suricata pipeline is stable** — Consistent MTTD across 10 independent runs, no drift

---

## Dissertation Metrics Engine

The Python-based evaluation engine (`calculate_dissertation_metrics.py`) quantifies the security posture by analyzing raw Wazuh alerts against timeline-stamped attack logs. Metrics include:

| Metric | Formula | Description |
| :--- | :--- | :--- |
| **Visibility Coverage** | Detected Steps / Total Steps × 100 | % of kill-chain steps that generated ≥1 SIEM alert |
| **Mean Time to Detect (MTTD)** | Σ(T_alert − T_attack) / N | Average latency (seconds) from attack execution to first alert |
| **True Positives** | Alerts within [−60s, +300s] of timestamped attack | Security events causally linked to known activity |
| **False Positives** | Alerts outside valid attack windows | Alert noise from non-attack periods |
| **Detection Precision** | TP / (TP + FP) | Specificity—how many alerts are actually relevant |
| **Sensitivity** | TP / (TP + FN) | Recall—percentage of attacks that generated at least one alert |

A configurable **Test Horizon** (seconds before test start) discards historical alerts to prevent residual noise from prior operations from inflating false-positive counts.

### Running the Complete Evaluation

**Option A: Single Test Run**
```bash
# Clear any prior alert state
docker exec -it wazuh.manager wazuh-control restart

# Wait ~30 seconds for wazuh to fully initialize
sleep 30

# Execute all attack scenarios (Scenarios A, B, C in sequence)
./attack_logic/attack_automation.sh

# Generate the metrics report
python3 scripts/calculate_dissertation_metrics.py
```

**Option B: Multi-Run Evaluation (Recommended for validation)**
```bash
# Execute 10 consecutive test cycles for statistical confidence
chmod +x scripts/run_10_iterations.sh
./scripts/run_10_iterations.sh
```

The metrics engine outputs:
- Raw alert counts per attack phase
- MTTD (mean & median) per scenario
- True/false positive breakdown
- Final detection precision and sensitivity scores
- Per-scenario visibility coverage (% of steps detected)
- Alerts not correlated to any known attack (noise analysis)

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

# Run the automated setup (interactive)
chmod +x setup_lab.sh
./setup_lab.sh
```

**What the setup script does:**
1. Detects your primary host network interface for MacVLAN bridge mapping
2. Creates VLAN-tagged subinterfaces (e.g., `eth0.90`, `eth0.95`, `eth0.96`, etc.)
3. Backs up and initializes the Keycloak realm with demo users
4. Generates SSL certificates for the Wazuh stack (one-time, stored in `wazuh_config/wazuh_indexer_ssl_certs/`)
5. Builds all custom container images (Keycloak with plugins, OpenPLC, Guacamole extensions)
6. Starts the full stack with `docker compose up -d`
7. Waits for service readiness (~2–3 minutes) before returning

**Stopping the lab:**
```bash
docker compose down -v  # -v removes persistent volumes (clears all data)
# or
docker compose down     # preserves Wazuh indices and Guacamole history
```

### Accessing the Lab

**Web Interfaces (via Pomerium with MFA):**

| Interface | URL | User | Group | Notes |
| :--- | :--- | :--- | :--- | :--- |
| HMI Dashboard | `https://hmi.localhost.pomerium.io` | engineer | `ot-engineer` | Real-time process monitoring |
| PLC Management | `https://plc.localhost.pomerium.io` | engineer | `ot-engineer` | Requires source IP = EWS (192.168.97.5) |
| Remote Desktop | `https://guacamole.localhost.pomerium.io` | engineer | `ot-engineer` | VNC/SSH to EWS; all sessions recorded |
| Simulation View | `https://simulation.localhost.pomerium.io` | engineer | `ot-engineer` | Reactor simulator HTTP API |
| Router Admin | `https://router.localhost.pomerium.io` | admin | `admin` | Firewall rules, routing tables |
| Keycloak | `http://keycloak.localhost.pomerium.io:8080` | — | — | Admin console at `/admin` (unauthenticated; configure realms/users) |
| SIEM Dashboard | `https://localhost:5601` | admin | — | OpenSearch Dashboards (direct, no Pomerium) |

**Demo Credentials:**
- **Engineer** — Username: `engineer` / Password: `engineer123` / OTP: Use your TOTP app (registered during first login)
- **Admin** — Username: `admin` / Password: `admin123`
- **Keycloak Console** — Username: `admin` / Password: `admin123`

**DNS Setup:**
Add to `/etc/hosts` (or configure a wildcard DNS):
```
127.0.0.1 localhost
127.0.0.1 hmi.localhost.pomerium.io
127.0.0.1 plc.localhost.pomerium.io
127.0.0.1 guacamole.localhost.pomerium.io
127.0.0.1 simulation.localhost.pomerium.io
127.0.0.1 router.localhost.pomerium.io
127.0.0.1 keycloak.localhost.pomerium.io
```

Alternatively, configure your system DNS to resolve `*.localhost.pomerium.io` to `127.0.0.1`.

### Troubleshooting Common Issues

**Docker build fails:**
```bash
# Ensure Docker daemon is running and you have sufficient disk space
docker system prune -a  # Clean up orphaned images
./setup_lab.sh          # Retry setup
```

**Pomerium redirects loop / 404 on routes:**
- Keycloak container may not be ready. Check logs: `docker logs keycloak`
- Ensure DNS is resolving to 127.0.0.1: `nslookup hmi.localhost.pomerium.io`
- Restart Pomerium: `docker restart pomerium`

**Can't access PLC console:**
- Verify you're accessing from the **EWS container** or Guacamole-proxied desktop
- PLC access is restricted to source IP `192.168.97.5` by Pomerium policy
- Check firewall rules: `docker exec router iptables -L FORWARD -v`

**SIEM alerts are empty:**
- Wazuh agents need ~30 seconds to initialize. Check manager logs: `docker logs wazuh.manager`
- Ensure Filebeat is shipping Suricata alerts: `docker logs router | grep filebeat`

**Scenario execution hangs:**
- Playwright may timeout if desktop is slow. Increase timeout in `attack_logic/tools/playwright_guacamole.py` (default: 60s per action)
- Check Guacamole daemon logs: `docker logs guacd`

---

## Project Structure

```
Zero-Trust-OT-lab/
├── scripts/                            # Automation & evaluation scripts
│   ├── run_10_iterations.sh            # 10-run stability test orchestrator
│   └── calculate_dissertation_metrics.py  # Metrics engine (alert → metric correlation)
│
├── results/                            # Evaluation results and artifacts
│   ├── metrics/                        # Text reports & attack results
│   └── logs/                           # Raw Wazuh alerts & execution logs
│
├── attacker/                           # Attack container build (Kali image)
│   ├── Dockerfile                      # Kali + Python + Playwright + VNC desktop build
│   └── start.sh                        # Container entrypoint
│
├── attack_logic/                       # Red-team automation (mounted into kali container)
│   ├── attack_automation.sh            # Main orchestrator (Scenarios A, B, C)
│   ├── scenarios/                      # Per-scenario shell scripts
│   │   ├── scenario_a.sh               # Network recon & Modbus protocol attacks
│   │   ├── scenario_b.sh               # Insider threat (Playwright automation)
│   │   └── scenario_c.sh               # Credential brute force & MFA bypass
│   └── tools/                          # Python attack libraries
│       ├── attack_suite.py             # Modbus scanning & protocol interaction
│       ├── playwright_guacamole.py     # Playwright automation (Guacamole VNC + PLC)
│       └── pomerium_plc_login.py       # Pomerium authentication simulation
│
├── plc/                                # OpenPLC container (Control L1)
│   ├── chemical.st                     # Reactor control logic
│   └── Dockerfile
│
├── pomerium/                           # Identity-Aware Proxy (IDMZ L3.5)
│   ├── config.yaml                     # ZT access policies & routes
│   └── Dockerfile
│
├── router/                             # Core Routing & IDS (All Zones)
│   ├── setup-firewall.sh               # IPtables micro-segmentation
│   ├── ot.rules                        # Suricata OT signatures (200+ rules)
│   └── Dockerfile
│
├── simulation/                         # Physical Process Simulator (L1)
│   ├── simulation.py                   # Modbus process model
│   └── Dockerfile
│
├── wazuh_config/                       # SIEM Rules & SIEM Configuration
│   ├── rules.xml                       # Custom correlation signatures
│   ├── decoders.xml                    # Logic for custom log parsing
│   └── generate-indexer-certs.yml      # Security credential automation
│
├── workstation/                        # Engineering Workstation (Ops L3)
│   ├── start.sh                        # VNC & Tooling initialization
│   └── Dockerfile
│
├── docker-compose.yml                  # Full-stack container orchestration
├── setup_lab.sh                        # Automated deployment script
├── .env                                # Local secrets (not committed)
└── README.md
```

### Key Files & Their Roles

- **[docker-compose.yml](docker-compose.yml)** — Defines all 13 services, networking, volumes, and healthchecks
- **[setup_lab.sh](setup_lab.sh)** — Entry point: creates VLAN interfaces, configures MacVLAN, builds images, deploys stack
- **[router/setup-firewall.sh](router/setup-firewall.sh)** — Executed inside router container; establishes default-deny iptables rules
- **[pomerium/config.yaml](pomerium/config.yaml)** — IAP routes and group-based access control (where zero-trust is enforced)
- **[wazuh_config/rules.xml](wazuh_config/rules.xml)** — Correlation rules (e.g., "File change + PLC login within 10min → Insider Threat alert")
- **[attack_logic/attack_automation.sh](attack_logic/attack_automation.sh)** — Parameterizable attack runner (can isolate per scenario); individual scenarios in `attack_logic/scenarios/`
- **[plc/chemical.st](plc/chemical.st)** — Control logic: reads pressure, sets setpoint, implements safety bounds

---

## Testing & Validation

### Quick Health Check
After deployment, verify all services are healthy:
```bash
# Check container status
docker compose ps

# Verify all services are "running" (not "restarting")
# Expected output: 19 containers (13 core services + 6 route-fixer sidecars), all healthy within 3 minutes
```

### Manual Scenario Testing
Test individual attack scenarios in isolation:

**Scenario A — Network Reconnaissance (from Enterprise/Kali container):**
```bash
docker exec kali bash -c "
  nmap -p 502 192.168.95.2  # Scan PLC
  modbus-cli -r 1-10 -c read-coils 192.168.95.2 502
"
# Check Wazuh dashboard for IDS alerts (1000041, 1000031)
```

**Scenario B — Insider Threat (automated):**
```bash
docker exec kali /bin/bash /home/kali/attack_logic/scenarios/scenario_b.sh
# Monitor: docker exec wazuh.manager tail -f /var/ossec/logs/alerts.json
# Expect: File modification alerts → PLC login → Pressure anomaly (within 2–3 minutes)
```

**Scenario C — Credential Brute Force (from CLI):**
```bash
docker exec kali /bin/bash /home/kali/attack_logic/scenarios/scenario_c.sh
# Check Keycloak logs: docker logs keycloak | grep "WARN\|ERROR"
# Wazuh should flag failed login attempts
```

### Validating Pomerium Zero-Trust Enforcement

**Test 1: Unauthorized source IP (should fail)**
```bash
# From outside EWS, try PLC access
curl -H "Authorization: Bearer $TOKEN" https://plc.localhost.pomerium.io/
# Expected: 403 Forbidden (source IP not in 192.168.97.5/32)
```

**Test 2: Missing group membership (should fail)**
```bash
# Create a test user in Keycloak with no groups
# Try to access HMI
# Expected: 403 Forbidden (not in ot-engineer group)
```

**Test 3: Bypassing MFA (should fail)**
```bash
# Use Keycloak REST API to get token without OTP
curl -X POST http://keycloak.localhost.pomerium.io:8080/realms/ot-lab/protocol/openid-connect/token \
  -d "username=engineer&password=engineer123&grant_type=password&client_id=..."
# Expected: 401 Unauthorized (MFA required)
```

---

## Customization & Extension

### Adding Custom Firewall Rules
Edit `router/ot.rules` (Suricata syntax):
```
alert modbus any any -> any any (msg:"Custom OT Rule"; modbus.func:3; sid:1000999; rev:1;)
```
Reload without restart:
```bash
docker exec router suricatasc -c "reload-rules"
```

### Modifying Correlation Rules
Edit `wazuh_config/rules.xml`:
```xml
<rule id="900001" level="7">
  <if_sid>5402,5406</if_sid>
  <same_source_ip />
  <timeframe>300</timeframe>
  <group>authentication,</group>
  <description>Multiple failed logins from same source</description>
</rule>
```
Reload: `docker restart wazuh.manager`

### Adding New OT Assets
1. Create a new container in `docker-compose.yml` with a fixed IP on the desired zone network
2. Add Wazuh agent configuration in `wazuh_config/wazuh_config` under `<agent-config>`
3. Add firewall rules in `router/setup-firewall.sh` to permit/deny traffic to/from the asset
4. Restart: `docker compose up -d`

### Extending the Simulator
Modify `simulation/simulation.py` to add new Modbus registers or change process parameters:
```python
self.reactor_state = {
    "pressure": 50.0,
    "temperature": 298.15,  # Add new parameter
    "setpoint": 70.0,
}
```
Rebuild: `docker compose up -d --build simulation`

---

## Performance & Optimization

### Resource Recommendations
- **CPU:** 4+ cores (Wazuh indexing is I/O intensive)
- **RAM:** 16 GB minimum (Wazuh stack alone needs ~8 GB)
- **Storage:** 20 GB free (Wazuh indices grow ~500 MB per scenario run)
- **Network:** Stable 1 Gbps interface for MacVLAN bridge

### Scaling for Production-Grade Research
- **Persistent Wazuh indices:** Don't run `docker compose down -v` between test runs; indices preserve historical data
- **Separate test runs:** Use `docker compose up -d --scale` to spin up multiple isolated stacks (requires unique port mappings)
- **Custom hostnames:** Modify `pomerium/config.yaml` to add reverse-proxy routes for additional OT assets

---

## Author & Citation

**Tryfon Iason Papatriantafyllou**  
*Zero-Trust Architecture Validation for Operational Technology Networks*

**Version:** 1.2 (Automated test suite with 10-run evaluation framework, stable SIEM pipeline validation)

If you use this lab for research, please cite:
```bibtex
@software{zero-trust-ot-lab,
  author = {Papatriantafyllou, Tryfon Iason},
  title = {Zero-Trust OT Security Lab},
  year = {2026},
  url = {https://github.com/yourusername/Zero-Trust-OT-lab}
}
```

---

## License

This project is provided as-is for educational and research purposes. See LICENSE for details.
