"""
explainer.py
------------
Calls Groq API (Llama3) for the top 20 flagged users + top 20 flagged events.
Saves explanations.json with structured risk assessments.
Requires: GROQ_API_KEY environment variable.
"""

import os
import json
import time
import sys

from groq import Groq
import pandas as pd

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")
OUT_FILE = os.path.join(BASE_DIR, "explanations.json")

# ──────────────────────────────────────────────────────────────────────────────
# Load flagged files (run detector first if missing)
# ──────────────────────────────────────────────────────────────────────────────
def _load(name):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        print(f"[WARN] {name} not found — running detector.py first.")
        import subprocess
        subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(__file__), "detector.py")],
                       check=True)
    return pd.read_csv(path)

flagged_users  = _load("flagged_users.csv")
flagged_events = _load("flagged_events.csv")

top_users  = flagged_users.head(20)
top_events = flagged_events.head(20)

# ──────────────────────────────────────────────────────────────────────────────
# Groq client
# ──────────────────────────────────────────────────────────────────────────────
client = Groq(api_key=os.environ["GROQ_API_KEY"])

SYSTEM_PROMPT = """You are a senior cybersecurity analyst at a Fortune 500 company.
Generate specific, actionable risk assessments.
Always use exact numbers from the data (e.g. 'inactive for 47 days' not 'account is inactive').
Map every finding to compliance frameworks: NIST AC-2, GDPR Article 32, SOX 302.
Recognize exceptions: CTO/CISO have broad access by design, contractors have short tenure,
new hires (<30 days) have unusual access patterns, on-call IT has off-hours access.
Never flag these as anomalous.
Always respond with valid JSON only — no markdown fences, no commentary outside JSON."""


def analyze_user(row: pd.Series) -> dict:
    """Call Groq to generate a structured risk assessment for one user."""
    user_data = {
        "user_id":         row.get("user_id", "UNKNOWN"),
        "username":        row.get("username", "unknown"),
        "department":      row.get("department", "unknown"),
        "job_title":       row.get("job_title", "unknown"),
        "privilege_level": row.get("privilege_level", "user"),
        "systems_access":  str(row.get("systems_access", "")),
        "days_inactive":   int(row.get("days_inactive", 0)),
        "is_active":       bool(row.get("is_active", True)),
        "risk_score":      float(row.get("risk_score", 0)),
        "severity":        str(row.get("severity", "LOW")),
        "hire_date":       str(row.get("hire_date", "")),
        "anomaly_flags": {
            "has_admin_inactive":  bool(row.get("has_admin_inactive", False)),
            "is_orphaned":         bool(row.get("is_orphaned", False)),
            "is_overprivileged":   bool(row.get("is_overprivileged", False)),
            "num_systems":         int(row.get("num_systems", 0)),
        },
    }

    prompt = f"""Analyze this user account and return a JSON risk assessment.

USER DATA:
{json.dumps(user_data, indent=2)}

Return ONLY a JSON object matching this exact schema:
{{
  "user_id": "...",
  "username": "...",
  "risk_score": <number>,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "findings": [
    {{
      "finding": "TYPE_CODE",
      "details": "Specific detail with exact numbers",
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "recommendation": "Exact actionable step"
    }}
  ],
  "blast_radius": {{
    "systems_at_risk": ["SYS1", "SYS2"],
    "estimated_records_exposed": <number>,
    "gdpr_fine_exposure": "€X or Y% revenue",
    "business_impact": "text"
  }},
  "compliance_violations": ["NIST AC-2", "GDPR Article 32"],
  "confidence": <0.0-1.0>,
  "suggested_actions": ["Step 1", "Step 2"],
  "next_escalation": "text"
}}"""

    try:
        response = client.chat.completions.create(
           model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:])
            raw = raw.rsplit("```", 1)[0]
        return json.loads(raw)
    except Exception as e:
        print(f"  [ERROR] {row.get('user_id')} — {e}")
        return {
            "user_id":   row.get("user_id", "UNKNOWN"),
            "username":  row.get("username", "unknown"),
            "risk_score": float(row.get("risk_score", 0)),
            "severity":   str(row.get("severity", "LOW")),
            "findings":   [{"finding": "ERROR", "details": str(e),
                             "severity": "LOW", "recommendation": "Retry"}],
            "blast_radius": {
                "systems_at_risk":           str(row.get("systems_access", "")),
                "estimated_records_exposed":  0,
                "gdpr_fine_exposure":         "Unknown",
                "business_impact":            "Analysis failed",
            },
            "compliance_violations": [],
            "confidence": 0.0,
            "suggested_actions":   ["Re-run analysis"],
            "next_escalation":     "Manual review required",
        }


def analyze_event(row: pd.Series) -> dict:
    """Call Groq to generate a structured risk assessment for one event."""
    event_data = {
        "timestamp":      str(row.get("timestamp", "")),
        "user_id":        row.get("user_id", "UNKNOWN"),
        "username":       row.get("username", "unknown"),
        "action":         row.get("action", ""),
        "resource":       row.get("resource", ""),
        "sensitivity":    row.get("resource_sensitivity", "low"),
        "status":         row.get("status", "success"),
        "hour_of_day":    int(row.get("hour_of_day", 12)),
        "is_weekend":     bool(row.get("is_weekend", False)),
        "is_after_hours": bool(row.get("is_after_hours", False)),
        "rowcount":       int(row.get("rowcount", 0)),
        "destination":    row.get("destination", "local_workstation"),
        "is_cross_dept":  bool(row.get("is_cross_dept", False)),
        "risk_score":     float(row.get("risk_score", 0)),
        "severity":       str(row.get("severity", "LOW")),
    }

    prompt = f"""Analyze this security event and return a JSON risk assessment.

EVENT DATA:
{json.dumps(event_data, indent=2)}

Return ONLY a JSON object matching this exact schema:
{{
  "event_index": <number>,
  "user_id": "...",
  "username": "...",
  "risk_score": <number>,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "findings": [
    {{
      "finding": "TYPE_CODE",
      "details": "Specific detail with exact numbers",
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "recommendation": "Exact actionable step"
    }}
  ],
  "compliance_violations": ["NIST AC-2"],
  "confidence": <0.0-1.0>,
  "suggested_actions": ["Step 1"],
  "next_escalation": "text"
}}"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.3,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:])
            raw = raw.rsplit("```", 1)[0]
        result = json.loads(raw)
        result["event_index"] = int(row.name)
        return result
    except Exception as e:
        print(f"  [ERROR] event {row.name} — {e}")
        return {
            "event_index":           int(row.name),
            "user_id":               row.get("user_id", "UNKNOWN"),
            "username":              row.get("username", "unknown"),
            "risk_score":            float(row.get("risk_score", 0)),
            "severity":              str(row.get("severity", "LOW")),
            "findings":              [{"finding": "ERROR", "details": str(e),
                                       "severity": "LOW", "recommendation": "Retry"}],
            "compliance_violations": [],
            "confidence":            0.0,
            "suggested_actions":     ["Re-run analysis"],
            "next_escalation":       "Manual review required",
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────────────
print(f"Analysing top {len(top_users)} users via Groq (Llama3)...")
user_explanations = []
for idx, row in top_users.iterrows():
    print(f"  [{idx+1:02d}/{len(top_users)}] {row.get('user_id')} — {row.get('username')}")
    result = analyze_user(row)
    user_explanations.append(result)
    time.sleep(1)

print(f"\nAnalysing top {len(top_events)} events via Groq (Llama3)...")
event_explanations = []
for idx, (df_idx, row) in enumerate(top_events.iterrows()):
    print(f"  [{idx+1:02d}/{len(top_events)}] event {df_idx} — {row.get('username')} / {row.get('action')}")
    result = analyze_event(row)
    event_explanations.append(result)
    time.sleep(1)

output = {
    "generated_at":     pd.Timestamp.now().isoformat(),
    "user_explanations":  user_explanations,
    "event_explanations": event_explanations,
}

with open(OUT_FILE, "w") as f:
    json.dump(output, f, indent=2)

print(f"\nexplainer.py complete. Saved {len(user_explanations)} user + "
      f"{len(event_explanations)} event explanations to {OUT_FILE}")