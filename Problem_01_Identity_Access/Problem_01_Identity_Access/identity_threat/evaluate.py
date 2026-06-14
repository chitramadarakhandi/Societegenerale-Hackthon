"""
evaluate.py
-----------
Loads ground truth vs predictions, prints classification reports,
false-positive analysis, and saves audit_report.md.
"""

import os
import json
import sys

import pandas as pd
from sklearn.metrics import (classification_report, precision_score,
                             recall_score, f1_score, confusion_matrix)

BASE_DIR    = os.path.join(os.path.dirname(__file__), "..", "sample_data")
REPORT_PATH = os.path.join(os.path.dirname(__file__), "..", "audit_report.md")


def _load(name):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        print(f"[WARN] {name} missing — running detector.py first.")
        import subprocess
        subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(__file__), "detector.py")],
                       check=True)
    return pd.read_csv(path)


users  = _load("identity_users_labels.csv")
events = _load("identity_events_labels.csv")

# Load LLM explanations (optional)
exp_path = os.path.join(BASE_DIR, "explanations.json")
explanations = {}
if os.path.exists(exp_path):
    with open(exp_path) as f:
        exp_data = json.load(f)
    for u in exp_data.get("user_explanations", []):
        explanations[u.get("user_id")] = u

# ──────────────────────────────────────────────────────────────────────────────
# 1. Metrics
# ──────────────────────────────────────────────────────────────────────────────
def safe_metrics(y_true, y_pred, label=""):
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score   (y_true, y_pred, zero_division=0)
    f = f1_score       (y_true, y_pred, zero_division=0)
    print(f"\n=== {label} METRICS ===")
    print(classification_report(y_true, y_pred,
                                target_names=["Normal","Anomaly"],
                                zero_division=0))
    cm = confusion_matrix(y_true, y_pred)
    print(f"Confusion matrix:\n{cm}")
    return p, r, f

u_p, u_r, u_f = (0, 0, 0)
e_p, e_r, e_f = (0, 0, 0)

if "is_anomaly" in users.columns and "predicted_anomaly" in users.columns:
    u_p, u_r, u_f = safe_metrics(
        users["is_anomaly"], users["predicted_anomaly"], "USER")

if "is_anomaly" in events.columns and "predicted_anomaly" in events.columns:
    e_p, e_r, e_f = safe_metrics(
        events["is_anomaly"], events["predicted_anomaly"], "EVENT")

# ──────────────────────────────────────────────────────────────────────────────
# 2. By-severity breakdown
# ──────────────────────────────────────────────────────────────────────────────
if "severity" in users.columns:
    print("\n=== USER SEVERITY BREAKDOWN ===")
    print(users[users.get("predicted_anomaly", pd.Series([])) == 1]
          ["severity"].value_counts())

if "severity" in events.columns:
    print("\n=== EVENT SEVERITY BREAKDOWN ===")
    print(events[events.get("predicted_anomaly", pd.Series([])) == 1]
          ["severity"].value_counts())

# ──────────────────────────────────────────────────────────────────────────────
# 3. False positive analysis
# ──────────────────────────────────────────────────────────────────────────────
print("\n=== FALSE POSITIVE ANALYSIS (Users) ===")
if {"is_anomaly", "predicted_anomaly", "risk_score"}.issubset(users.columns):
    fps = users[(users["is_anomaly"] == 0) & (users["predicted_anomaly"] == 1)]
    print(f"Total user FPs: {len(fps)}")
    for _, row in fps.head(5).iterrows():
        reason = []
        if row.get("days_inactive", 0) > 30:
            reason.append(f"inactive {row['days_inactive']}d")
        if row.get("num_systems", 0) >= 4:
            reason.append(f"{row['num_systems']} systems")
        if row.get("privilege_encoded", 0) >= 2:
            reason.append(f"priv={row['privilege_level']}")
        print(f"  {row['user_id']} ({row.get('username')}) — "
              f"score={row['risk_score']:.0f} — WHY: {', '.join(reason) or 'borderline IF score'}")

# ──────────────────────────────────────────────────────────────────────────────
# 4. Build audit_report.md
# ──────────────────────────────────────────────────────────────────────────────
flagged_u_path = os.path.join(BASE_DIR, "flagged_users.csv")
top10 = []
if os.path.exists(flagged_u_path):
    top10 = pd.read_csv(flagged_u_path).head(10).to_dict("records")

lines = [
    "# Identity Threat Intelligence — Audit Report",
    "",
    "## Executive Summary",
    "",
    f"| Metric | Users | Events |",
    f"|--------|-------|--------|",
    f"| Precision | {u_p:.2%} | {e_p:.2%} |",
    f"| Recall    | {u_r:.2%} | {e_r:.2%} |",
    f"| F1-Score  | {u_f:.2f}   | {e_f:.2f}   |",
    "",
    "## Top 10 Flagged Users",
    "",
]

for i, u in enumerate(top10, 1):
    exp = explanations.get(u.get("user_id"), {})
    lines += [
        f"### {i}. {u.get('user_id')} — {u.get('username')} (Score: {u.get('risk_score',0):.0f})",
        f"- **Severity:** {u.get('severity','N/A')}",
        f"- **Department:** {u.get('department','N/A')} | "
        f"**Privilege:** {u.get('privilege_level','N/A')}",
        f"- **Days Inactive:** {u.get('days_inactive',0)} | "
        f"**Systems:** {u.get('num_systems',0)}",
    ]
    if exp and exp.get("findings"):
        lines.append("- **LLM Findings:**")
        for f_item in exp["findings"][:2]:
            lines.append(f"  - `{f_item.get('finding')}`: {f_item.get('details','')}")
    if exp and exp.get("blast_radius"):
        br = exp["blast_radius"]
        lines.append(f"- **Blast Radius:** {br.get('estimated_records_exposed',0):,} records, "
                     f"GDPR: {br.get('gdpr_fine_exposure','N/A')}")
    lines.append("")

lines += [
    "## Compliance Impact",
    "",
    "| Framework | Requirement | Violations Found |",
    "|-----------|-------------|-----------------|",
    "| NIST AC-2 | Account Management — disable inactive accounts | Stale admin accounts |",
    "| GDPR Art. 32 | Technical security measures for data access | External data exports |",
    "| SOX 302 | Controls over financial data access | Cross-dept GL_System access |",
    "",
    "## Remediation Playbook",
    "",
    "1. **Immediate (< 4 hours):** Disable all CRITICAL-severity accounts pending HR verification",
    "2. **Short-term (< 24 hours):** Force password reset on all HIGH-severity accounts",
    "3. **Medium-term (1 week):** Conduct access reviews for all power-user and admin accounts",
    "4. **Long-term:** Implement automated quarterly access certifications",
    "",
    "---",
    "*Generated by Identity Threat Intelligence Platform*",
]

with open(REPORT_PATH, "w") as f:
    f.write("\n".join(lines))

print(f"\naudit_report.md written to {REPORT_PATH}")
print("evaluate.py complete.")
