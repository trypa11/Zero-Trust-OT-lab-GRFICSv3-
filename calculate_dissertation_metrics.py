#!/usr/bin/env python3
"""
Dissertation Metrics Engine — Zero-Trust OT Lab Validation
===========================================================
Parses the attack automation output and correlates each attack step
with Wazuh SIEM alerts to compute:
  - Per-scenario and overall Visibility Coverage
  - Mean / Median Time to Detect (MTTD)
  - MITRE ATT&CK tactic mapping for each step
  - Detailed per-step detection evidence
"""

import csv
import re
import statistics
from datetime import datetime, timedelta

# ─── Configuration ───────────────────────────────────────────────────────────

ATTACK_LOG  = "attack_results.txt"
WAZUH_CSV   = "latest_events.csv"
OUTPUT_FILE = "dissertation_metrics_report.txt"

# Attack log timestamps are in UTC+3 (Athens); SIEM CSV is UTC.
TZ_OFFSET_HOURS = -3

# ─── MITRE ATT&CK Tactic Mapping ────────────────────────────────────────────

MITRE_MAP = {
    "Nmap":             ("TA0043 / T0846",  "Reconnaissance / Gather Victim Network Info"),
    "Modbus Recon":     ("TA0102 / T0861",  "Collection / Point & Tag Identification"),
    "Identity Access":  ("TA0001 / T0866",  "Initial Access / Exploitation of Remote Services"),
    "VNC Session":      ("TA0008 / T0886",  "Lateral Movement / Remote Services"),
    "FIM":              ("TA0040 / T0831",  "Impact / Manipulation of Control"),
    "PLC Login":        ("TA0006 / T0859",  "Credential Access / Valid Accounts"),
    "Sabotage":         ("TA0040 / T0831",  "Impact / Manipulation of Control"),
    "Brute Force":      ("TA0006 / T0110",  "Credential Access / Brute Force"),
    "FIM Restore":      ("TA0005 / T1070",  "Defense Evasion / Indicator Removal"),
}

# ─── Wazuh Rule Mapping ─────────────────────────────────────────────────────
# Maps each attack type to the Wazuh rule IDs that constitute a valid detection.

RULE_MAP = {
    # Scenario A: Reconnaissance
    "Nmap":             ["100035", "100042"],
    "Modbus Recon":     ["100029", "100041"],
    # Scenario B: Insider Threat
    "Identity Access":  ["100502", "86601"],   # Keycloak auth event or Suricata TLS
    "VNC Session":      ["86601"],             # Suricata detects the TLS tunnel
    "FIM":              ["100210"],             # Wazuh syscheck realtime (chemical.st)
    "PLC Login":        ["100060", "100502", "86601"],
    "Sabotage":         ["100026", "100020"],
    "FIM Restore":      ["100210"],
    # Scenario C: Identity Brute Force & MFA
    "Brute Force":      ["100502", "100520"],
}

# ─── Scenario Descriptions ──────────────────────────────────────────────────

SCENARIO_DESCRIPTIONS = {
    "SCENARIO A": (
        "OT Network & Protocol Reconnaissance Audit",
        "External adversary (Kali) probes the segmented OT network to discover "
        "assets across all Purdue levels. The Zero-Trust firewall should block "
        "every cross-zone probe and generate SIEM alerts."
    ),
    "SCENARIO B": (
        "Insider Threat — PLC Program Sabotage via Remote Access",
        "Compromised insider authenticates through the Pomerium/Keycloak gateway, "
        "establishes a VNC session to the EWS via Guacamole, modifies the PLC "
        "program (chemical.st) with sabotage values, and uploads it to the PLC. "
        "Detection relies on FIM, identity logs, and Suricata proxy monitoring."
    ),
    "SCENARIO C": (
        "Identity Brute Force & MFA Enforcement Validation",
        "External adversary attempts credential stuffing against Keycloak. "
        "Validates that MFA enforcement blocks access even with a correct "
        "password, and that the SIEM flags all failed authentication attempts."
    ),
}

# ─── Helper Functions ────────────────────────────────────────────────────────

def strip_ansi(text):
    """Remove ANSI colour codes from terminal output."""
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

def classify_step(line):
    """Classify a log step line into an attack type for SIEM correlation."""
    # Scenario A
    if any(k in line for k in ["Auditing", "Segmentation", "IDMZ",
                                "Enterprise", "Supervisory", "Control Connectivity"]):
        return "Nmap"
    if any(k in line for k in ["Mdbget", "Modbus Scan", "extract PLC registers"]):
        return "Modbus Recon"

    # Scenario B
    if any(k in line for k in ["Gateway (Guacamole)", "Navigating to Zero-Trust Gateway"]):
        return "Identity Access"
    if any(k in line for k in ["remote desktop session (VNC)", "VNC session",
                                "Opening remote desktop"]):
        return "VNC Session"
    if "Modifying PLC program" in line:
        return "FIM"
    if any(k in line for k in ["PLC Console", "Uploading malicious"]):
        return "PLC Login"
    if "Restoring PLC values" in line:
        return "FIM Restore"

    # Scenario C
    if any(k in line for k in ["Brute-forcing", "brute force", "Brute Force",
                                "Simulating Keycloak"]):
        return "Brute Force"
    if any(k in line for k in ["MFA", "Correct password", "OTP",
                                "Identity Verification"]):
        return "Brute Force"

    return "Ignore"


def extract_step_description(line):
    """Pull a human-readable description from a step log line."""
    text = line.replace("[*]", "").strip()
    # Remove the leading "Step N:" prefix and return the rest
    m = re.match(r"Step\s+\d+\s*:\s*(.*)", text)
    return m.group(1).strip() if m else text


# ─── Parsers ─────────────────────────────────────────────────────────────────

def parse_attack_logs(filepath):
    """Parse attack_results.txt and extract timestamped attack steps."""
    attacks = []
    current_scenario = "Unknown"
    pending_step = None          # (step_name, type, description)

    with open(filepath, 'r') as f:
        for raw_line in f:
            line = strip_ansi(raw_line).strip()
            if not line:
                continue

            # Detect scenario header  ──  "==== SCENARIO X: ... ===="
            if "SCENARIO" in line and "====" in line:
                cleaned = line.strip("= ").strip()
                # Extract e.g. "SCENARIO B"
                m = re.match(r"(SCENARIO\s+[A-Z])", cleaned)
                if m:
                    current_scenario = m.group(1)
                continue

            # Detect a step line  ──  "[*] Step N: ..."
            if line.startswith("[*]"):
                step_text = line.replace("[*]", "").strip()
                step_type = classify_step(step_text)

                if step_type != "Ignore":
                    # Extract "Step N" as short name
                    m = re.match(r"(Step\s+\d+)", step_text)
                    short_name = m.group(1) if m else step_text[:20]
                    description = extract_step_description(line)
                    pending_step = (short_name, step_type, description)
                else:
                    pending_step = None
                continue

            # Detect timestamp  ──  "[TIME] 2026-04-20 10:30:26.546"
            time_match = re.search(r"\[TIME\].*?([\d\-]{10} [\d:.]+)", line)
            if time_match and pending_step:
                try:
                    ts = datetime.strptime(time_match.group(1),
                                           "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    continue

                short_name, step_type, description = pending_step
                attacks.append({
                    "scenario":    current_scenario,
                    "step_name":   short_name,
                    "description": description,
                    "type":        step_type,
                    "start":       ts,
                })
                pending_step = None    # consume it

    return attacks


def parse_wazuh_csv(filepath):
    """Parse the SIEM CSV and extract alerts with timestamps."""
    alerts = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_raw = (row.get('timestamp') or row.get('@timestamp') or "").strip('"')
            dt = None
            # ISO format: 2026-04-19T21:06:56.144+0000
            try:
                dt = datetime.strptime(ts_raw[:23], "%Y-%m-%dT%H:%M:%S.%f")
            except (ValueError, IndexError):
                pass
            # Kibana format: "Apr 18, 2026 @ 18:27:30.612"
            if not dt:
                try:
                    date_part, time_part = ts_raw.split("@ ")
                    dt = datetime.strptime(
                        f"{date_part.strip()} {time_part.strip()}",
                        "%b %d, %Y %H:%M:%S.%f")
                except (ValueError, IndexError):
                    continue
            if dt:
                alerts.append({
                    "timestamp": dt,
                    "rule_id":   row.get('rule.id', ''),
                    "desc":      row.get('rule.description', ''),
                })
    return sorted(alerts, key=lambda x: x['timestamp'])


# ─── Correlation Engine ─────────────────────────────────────────────────────

def correlate(attacks, alerts):
    """Match each attack step to the closest valid SIEM alert and calculate FPs."""
    used = set()
    results = []

    # Flatten tracked rule IDs
    tracked_rules = set()
    for rules in RULE_MAP.values():
        tracked_rules.update(rules)

    tp_alerts = set()
    fp_alerts = []



    # Determine the test window boundary to ignore historical alerts from previous runs
    test_start_utc = min(atk['start'] for atk in attacks) + timedelta(hours=TZ_OFFSET_HOURS)
    test_horizon   = test_start_utc - timedelta(seconds=60)

    # First pass: Identify the BEST match for each attack step for reporting
    for atk in attacks:
        search_ts = atk['start'] + timedelta(hours=TZ_OFFSET_HOURS)
        possible  = RULE_MAP.get(atk['type'], [])
        best      = None

        for alert in alerts:
            # Ignore alerts before the test began
            if alert['timestamp'] < test_horizon:
                continue
                
            if id(alert) in used:
                continue
            diff = (alert['timestamp'] - search_ts).total_seconds()
            if alert['rule_id'] in possible and -60 <= diff <= 300:
                best = alert
                if atk['type'] != "Nmap":   # Nmap alerts are shared across steps conceptually, but consumed for metrics
                    used.add(id(alert))
                break

        if best:
            delta = max(0, (best['timestamp'] - search_ts).total_seconds())
            desc  = best['desc'][:60] + "..." if len(best['desc']) > 60 else best['desc']
            results.append({
                **atk,
                "status":    "DETECTED",
                "mttd":      delta,
                "mttd_str":  f"{delta:.3f}s",
                "rule_id":   best['rule_id'],
                "rule_info": f"Rule {best['rule_id']}: {desc}",
            })
        else:
            results.append({
                **atk,
                "status":    "MISSED",
                "mttd":      None,
                "mttd_str":  "N/A",
                "rule_id":   "-",
                "rule_info": "No matching SIEM alert within correlation window.",
            })

    # Second pass: Mathematically classify ALL ingested alerts (within test horizon) as TP or FP
    for alert in alerts:
        if alert['timestamp'] < test_horizon or alert['rule_id'] not in tracked_rules:
            continue
            
        # Check if this alert falls into the valid time window of ANY attack step that expects it
        is_tp = False
        for atk in attacks:
            possible = RULE_MAP.get(atk['type'], [])
            if alert['rule_id'] in possible:
                search_ts = atk['start'] + timedelta(hours=TZ_OFFSET_HOURS)
                diff = (alert['timestamp'] - search_ts).total_seconds()
                if -60 <= diff <= 300:
                    is_tp = True
                    break
        
        if is_tp:
            tp_alerts.add(id(alert))
        else:
            fp_alerts.append(alert)

    # Calculate metrics
    total_tp = len(tp_alerts)
    total_fp = len(fp_alerts)
    precision = (total_tp / (total_tp + total_fp) * 100) if (total_tp + total_fp) > 0 else 0.0

    metrics = {
        "tp_count": total_tp,
        "fp_count": total_fp,
        "precision": precision
    }

    return results, used, metrics


# ─── Report Generator ───────────────────────────────────────────────────────

def generate_report(results, total_alerts, unique_events, metrics):
    """Build the full dissertation-grade report as a list of text lines."""
    W = 100   # report width
    lines = []

    def out(t=""):
        lines.append(t)

    # ── Header ───────────────────────────────────────────────────────────
    out("=" * W)
    out("DISSERTATION METRICS REPORT".center(W))
    out("Zero-Trust Architecture for ICS/OT — Defence-in-Depth Validation".center(W))
    out("=" * W)
    out(f"  Report generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Attack log       : {ATTACK_LOG}")
    out(f"  SIEM data source : {WAZUH_CSV}  ({total_alerts} alerts ingested)")
    out(f"  Timezone offset  : Attack logs UTC+3 → SIEM UTC  (Δ = {TZ_OFFSET_HOURS}h)")
    out("")

    # ── Group by scenario ────────────────────────────────────────────────
    scenarios = {}
    for r in results:
        s = r['scenario']
        scenarios.setdefault(s, []).append(r)

    # ── Attack Steps Inventory ───────────────────────────────────────────
    out("─" * W)
    out("  ATTACK STEPS INVENTORY".center(W))
    out("─" * W)
    out(f"  {'#':<4} {'Scenario':<14} {'Type':<18} {'MITRE Tactic':<26} {'Description'}")
    out("  " + "─" * (W - 4))
    for i, r in enumerate(results, 1):
        mitre_id = MITRE_MAP.get(r['type'], ("—", "—"))[0]
        desc = r['description'][:40] + "..." if len(r['description']) > 40 else r['description']
        out(f"  {i:<4} {r['scenario']:<14} {r['type']:<18} {mitre_id:<26} {desc}")
    out("")

    # ── Per-Scenario Analysis ────────────────────────────────────────────
    out("=" * W)
    out("  DETAILED SCENARIO ANALYSIS".center(W))
    out("=" * W)

    global_detected = 0
    global_total    = 0
    global_mttds    = []

    for scen_key, steps in scenarios.items():
        title, desc = SCENARIO_DESCRIPTIONS.get(
            scen_key,
            (scen_key, "No description available.")
        )

        out("")
        out(f"  ┌{'─' * (W - 4)}┐")
        out(f"  │ {scen_key}: {title}".ljust(W - 3) + "│")
        out(f"  ├{'─' * (W - 4)}┤")
        # Word-wrap the description to fit within the box
        words = desc.split()
        line_buf = "  │ "
        for w in words:
            if len(line_buf) + len(w) + 1 > W - 3:
                out(line_buf.ljust(W - 3) + "│")
                line_buf = "  │ " + w
            else:
                line_buf += (" " if len(line_buf) > 4 else "") + w
        if line_buf.strip("│ "):
            out(line_buf.ljust(W - 3) + "│")
        out(f"  └{'─' * (W - 4)}┘")
        out("")

        col_w = (4, 32, 10, 10, 42)
        hdr = (f"{'#':<{col_w[0]}}"
               f"{'Attack Step':<{col_w[1]}}"
               f"{'Status':<{col_w[2]}}"
               f"{'MTTD':<{col_w[3]}}"
               f"{'Matched SIEM Evidence':<{col_w[4]}}")
        out(f"  {hdr}")
        out("  " + "─" * (sum(col_w)))

        scen_detected = 0
        scen_mttds    = []

        for i, r in enumerate(steps, 1):
            desc_short = r['description'][:30] + ".." if len(r['description']) > 30 else r['description']
            rule_short = r['rule_info'][:40] + ".." if len(r['rule_info']) > 40 else r['rule_info']
            marker = "✓" if r['status'] == "DETECTED" else "✗"
            row = (f"{marker} {i:<{col_w[0] - 2}}"
                   f"{desc_short:<{col_w[1]}}"
                   f"{r['status']:<{col_w[2]}}"
                   f"{r['mttd_str']:<{col_w[3]}}"
                   f"{rule_short}")
            out(f"  {row}")

            if r['status'] == "DETECTED":
                scen_detected += 1
                scen_mttds.append(r['mttd'])
                global_mttds.append(r['mttd'])

        scen_total = len(steps)
        global_detected += scen_detected
        global_total    += scen_total

        out("  " + "─" * (sum(col_w)))
        pct = (scen_detected / scen_total * 100) if scen_total else 0
        out(f"  → Visibility Coverage : {pct:.1f}%  ({scen_detected}/{scen_total} steps detected)")
        if scen_mttds:
            out(f"  → Mean MTTD           : {statistics.mean(scen_mttds):.3f}s")
            out(f"  → Median MTTD         : {statistics.median(scen_mttds):.3f}s")
        out("")

    # ── MITRE ATT&CK Coverage Table ──────────────────────────────────────
    out("=" * W)
    out("  MITRE ATT&CK ICS COVERAGE MATRIX".center(W))
    out("=" * W)
    out(f"  {'Attack Type':<18} {'Tactic / Technique':<30} {'Description':<36} {'Detected'}")
    out("  " + "─" * 92)

    # Deduplicate by type
    seen_types = set()
    for r in results:
        if r['type'] not in seen_types:
            seen_types.add(r['type'])
            m_id, m_desc = MITRE_MAP.get(r['type'], ("—", "—"))
            # Check if ANY step of this type was detected
            any_detected = any(
                x['status'] == 'DETECTED'
                for x in results if x['type'] == r['type']
            )
            marker = "  ✓" if any_detected else "  ✗"
            m_desc_short = m_desc[:34] + ".." if len(m_desc) > 34 else m_desc
            out(f"  {r['type']:<18} {m_id:<30} {m_desc_short:<36} {marker}")
    out("")

    # ── Final Summary ────────────────────────────────────────────────────
    coverage  = (global_detected / global_total * 100) if global_total else 0
    avg_mttd  = statistics.mean(global_mttds) if global_mttds else 0
    med_mttd  = statistics.median(global_mttds) if global_mttds else 0

    out("=" * W)
    out("  FINAL DISSERTATION METRICS SUMMARY".center(W))
    out("=" * W)
    out("")
    out(f"  ┌──────────────────────────────────────────────────────────────┐")
    out(f"  │  Overall ZT Visibility Coverage :  {coverage:>6.1f}%  ({global_detected}/{global_total} steps)      │")
    out(f"  │  Mean Time to Detect  (MTTD)    :  {avg_mttd:>6.3f}s                    │")
    out(f"  │  Median Time to Detect (MTTD)   :  {med_mttd:>6.3f}s                    │")
    out(f"  │  True Positives (TP)           :  {metrics['tp_count']:>6d}                       │")
    out(f"  │  False Positives (FP)          :  {metrics['fp_count']:>6d}                       │")
    out(f"  │  Detection Precision           :  {metrics['precision']:>6.1f}%                       │")
    out(f"  │  Total SIEM Alerts Ingested      :  {total_alerts:>6d}                       │")
    out(f"  └──────────────────────────────────────────────────────────────┘")
    out("")
    out("=" * W)
    out("  METRIC CALCULATION METHODOLOGY & FORMULAS".center(W))
    out("=" * W)
    out("")
    out("  1. Visibility Coverage (%)")
    out("     Formula: (Total Steps Detected / Total Steps Attempted) * 100")
    out("     Definition: Measures the security stack's ability to provide end-to-end auditability")
    out("     across the entire kill-chain.")
    out("")
    out("  2. Mean/Median Time to Detect (MTTD)")
    out("     Formula (Mean): Σ(Detection_Timestamp - Attack_Timestamp) / N_Detected")
    out("     Definition: Quantifies the responsiveness of the SIEM pipeline. Median is used to")
    out("     offset outliers caused by network batching or log ingestion delays (e.g., Suricata).")
    out("")
    out("  3. True Positives (TP)")
    out("     Definition: Security alerts matching known attack signatures that occur within a")
    out("     [-60s, +300s] time window of a logged attack step execution.")
    out("")
    out("  4. False Positives (FP)")
    out("     Definition: Security alerts from tracked rules that occur outside the valid attack")
    out("     windows. This measures the 'noise' or 'alarm fatigue' generated by the system.")
    out("")
    out("  5. Detection Precision")
    out("     Formula: TP / (TP + FP)")
    out("     Evaluation: 100% Precision indicate that the Zero-Trust correlation rules are")
    out("     highly specific and only fire in response to verified malicious activity.")
    out("")
    out("  6. Scientific Window Correlation (Test Horizon)")
    out("     Logic: All SIEM alerts occurring before the 'Test Start' (T_first_step - 60s) are")
    out("     mathematically discarded to prevent historical noise from skewing live metrics.")
    out("")
    out("=" * W)
    out("  --- END OF DISSERTATION METRICS REPORT ---")
    out("=" * W)
    out("")
    return lines


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print(f"[*] Loading attack logs from {ATTACK_LOG}...")
    attacks = parse_attack_logs(ATTACK_LOG)
    valid   = [a for a in attacks if a['type'] != 'Ignore']
    print(f"    {len(valid)} attack steps identified.")

    print(f"[*] Loading SIEM alerts from {WAZUH_CSV}...")
    alerts = parse_wazuh_csv(WAZUH_CSV)
    print(f"    {len(alerts)} alerts ingested.")

    print("[*] Running correlation engine...")
    results, unique_events, metrics = correlate(valid, alerts)

    detected = sum(1 for r in results if r['status'] == 'DETECTED')
    print(f"    {detected}/{len(results)} steps matched to SIEM alerts.")
    print(f"    Precision calculated at {metrics['precision']:.1f}% ({metrics['tp_count']} TP / {metrics['fp_count']} FP).")

    print(f"[*] Generating report → {OUTPUT_FILE}")
    report_lines = generate_report(results, len(alerts), unique_events, metrics)

    # Print to terminal
    for line in report_lines:
        print(line)

    # Write to file
    with open(OUTPUT_FILE, 'w') as f:
        f.write("\n".join(report_lines) + "\n")

    print(f"\n[+] Report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
