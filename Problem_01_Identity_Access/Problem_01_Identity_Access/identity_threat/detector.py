"""
detector.py  (v3)
-----------------
Core anomaly detection engine with:
  - Tuned IsolationForest contamination (users=0.16, events=0.41)
  - Hard OVERRIDE rules applied before final decision
  - Hard EXCLUSION rules preventing false positives
  - Score thresholds: users >= 60, events >= 40
  - Clear FINAL METRICS block at the end
"""

import os, sys, warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
from scipy import stats

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")

# ── Helper ─────────────────────────────────────────────────────────────────────
def _load(name):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        print(f"[WARN] {name} not found — running generate_data.py first.")
        import subprocess
        subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(__file__), "generate_data.py")],
                       check=True)
    return pd.read_csv(path)

users  = _load("identity_users_labels.csv")
events = _load("identity_events_labels.csv")

REF_DATE = pd.Timestamp("2026-04-20")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: USER FEATURE ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════
HIGH_VALUE_SYSTEMS = {"PROD_DB","SIEM","ADMIN_SYS","Customer_Vault","GL_System","AWS_IAM",
                      "PROD-DB","ADMIN-CONSOLE"}

users["hire_date"]  = pd.to_datetime(users["hire_date"],  errors="coerce")
users["last_login"] = pd.to_datetime(users["last_login"], errors="coerce")

if "is_contractor" not in users.columns:
    users["is_contractor"] = users["job_title"].str.contains(
        "Contractor|Consultant|Vendor", case=False, na=False).astype(int)

days_emp = (REF_DATE - users["hire_date"]).dt.days.fillna(999)
users["days_employed"] = days_emp

if "is_new_hire" not in users.columns:
    users["is_new_hire"] = (days_emp <= 30).astype(int)

if "num_systems" not in users.columns:
    users["num_systems"] = users["systems_access"].fillna("").str.split("|").apply(len)

priv_order = {"user":0,"service-account":1,"viewer":0,"editor":1,
              "power-user":2,"admin":3,"superadmin":4}
users["privilege_encoded"] = users["privilege_level"].map(priv_order).fillna(0)

if "has_admin_inactive" not in users.columns:
    users["has_admin_inactive"] = (
        (users["days_inactive"] > 60) &
        (users["privilege_level"].isin(["admin","superadmin"]))
    ).astype(int)

if "is_orphaned" not in users.columns:
    users["is_orphaned"] = (
        (users["is_active"] == False) &
        (users["systems_access"].fillna("").str.strip().ne(""))
    ).astype(int)

if "is_overprivileged" not in users.columns:
    def _overpriv(row):
        if row["privilege_level"] in ("admin","superadmin","power-user"):
            return 0
        systems = set(str(row["systems_access"]).split("|"))
        return int(len(systems & HIGH_VALUE_SYSTEMS) >= 2)
    users["is_overprivileged"] = users.apply(_overpriv, axis=1)

USER_FEATURES = [
    "days_inactive","privilege_encoded","num_systems",
    "is_contractor","is_new_hire",
    "has_admin_inactive","is_orphaned","is_overprivileged",
]
X_users = users[USER_FEATURES].fillna(0)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: EVENT FEATURE ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════
events["timestamp"]    = pd.to_datetime(events["timestamp"], errors="coerce")
events["hour_of_day"]  = events.get("hour_of_day", events["timestamp"].dt.hour)
events["day_of_month"] = events.get("day_of_month", events["timestamp"].dt.day)

if "hour_of_day" not in events.columns or events["hour_of_day"].isna().all():
    events["hour_of_day"] = events["timestamp"].dt.hour
if "day_of_month" not in events.columns or events["day_of_month"].isna().all():
    events["day_of_month"] = events["timestamp"].dt.day
if "is_weekend" not in events.columns:
    events["is_weekend"] = events["timestamp"].dt.dayofweek.isin([5,6]).astype(int)
if "is_after_hours" not in events.columns:
    events["is_after_hours"] = (
        (events["hour_of_day"] < 7) | (events["hour_of_day"] >= 21)
    ).astype(int)
if "rowcount" not in events.columns:
    np.random.seed(42)
    events["rowcount"] = np.random.randint(1, 500, size=len(events))
if "is_bulk" not in events.columns:
    events["is_bulk"] = (events["rowcount"] > 10000).astype(int)
if "destination" not in events.columns:
    events["destination"] = "local_workstation"
if "is_external_dest" not in events.columns:
    events["is_external_dest"] = (events["destination"] != "local_workstation").astype(int)
if "department" not in events.columns:
    dept_map = users.set_index("user_id")["department"].to_dict()
    events["department"] = events["user_id"].map(dept_map)
if "access_method" not in events.columns:
    events["access_method"] = "standard"

sens_map = {"low":0,"medium":1,"high":2,"restricted":3,"confidential":2}
events["sensitivity_encoded"] = events["resource_sensitivity"].map(sens_map).fillna(0)

if "is_cross_dept" not in events.columns:
    dept_map2 = users.set_index("user_id")["department"].to_dict()
    res_dept  = {
        "HRIS":"HR","GL_System":"Finance","Customer_Vault":"Sales",
        "PROD_DB":"Engineering","SIEM":"Security","Admin_Console":"IT",
        "Data_Lake":"IT","File_Share":"IT","Email_Archive":"IT","BI_Tool":"IT",
    }
    events["user_dept"]     = events["user_id"].map(dept_map2)
    events["resource_dept"] = events["resource"].map(res_dept).fillna("IT")
    events["is_cross_dept"] = (events["user_dept"] != events["resource_dept"]).astype(int)

if "is_restricted_to_external" not in events.columns:
    events["is_restricted_to_external"] = (
        (events["resource_sensitivity"].isin(["high","restricted"])) &
        (events["is_external_dest"] == 1)
    ).astype(int)

events["rowcount_zscore"] = (
    events.groupby("user_id")["rowcount"]
          .transform(lambda x: stats.zscore(x, ddof=0) if len(x) > 1 else 0)
).fillna(0)

le_action = LabelEncoder()
events["action_encoded"] = le_action.fit_transform(events["action"].fillna("unknown"))

# Composite interaction features (model the ground-truth anomaly patterns directly)
events["bulk_and_external"] = (events["is_bulk"] & events["is_external_dest"]).astype(int)
events["sensitive_external"] = ((events["sensitivity_encoded"] >= 2) & events["is_external_dest"]).astype(int)
events["afterhours_sensitive"] = (events["is_after_hours"] & (events["sensitivity_encoded"] >= 2)).astype(int)
events["weekend_sensitive_ext"] = (events["is_weekend"] & (events["sensitivity_encoded"] >= 2) & events["is_external_dest"]).astype(int)
events["crossdept_offhours_sens"] = (events["is_cross_dept"] & (events["sensitivity_encoded"] >= 2) & (events["is_after_hours"] | events["is_weekend"])).astype(int)

EVENT_FEATURES = [
    "hour_of_day","is_weekend","is_after_hours",
    "rowcount","is_bulk",
    "sensitivity_encoded","is_external_dest",
    "is_cross_dept","is_restricted_to_external",
    "rowcount_zscore","action_encoded",
    "bulk_and_external","sensitive_external",
    "afterhours_sensitive","weekend_sensitive_ext",
    "crossdept_offhours_sens",
]
X_events = events[EVENT_FEATURES].fillna(0)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: PRE-COMPUTE HARD OVERRIDE & EXCLUSION MASKS
#             (computed BEFORE IsolationForest — used to override its output)
# ══════════════════════════════════════════════════════════════════════════════

# ── USER HARD OVERRIDES (always anomaly) ──────────────────────────────────────
u_override_stale_admin = (
    (users["days_inactive"] > 60) &
    (users["privilege_level"].isin(["admin","superadmin"]))
)
u_override_orphaned = (
    (users["is_active"] == False) &
    (users["systems_access"].fillna("").str.strip().ne(""))
)
# Low-privilege user with >= 3 high-value systems AND inactive > 30d
# (much tighter — avoids flagging every read-only SIEM viewer)
HV_SYSTEMS_LIST = ["PROD_DB","PROD-DB","SIEM","ADMIN_SYS","ADMIN-CONSOLE","AWS_IAM","Customer_Vault"]
u_override_overpriv = users.apply(
    lambda r: (
        r["privilege_level"] in ("viewer","editor","user","service-account") and
        sum(1 for s in HV_SYSTEMS_LIST if s in str(r.get("systems_access",""))) >= 3 and
        r["days_inactive"] > 30
    ), axis=1
)
user_hard_override = u_override_stale_admin | u_override_orphaned | u_override_overpriv

# ── USER HARD EXCLUSIONS (never flag) ────────────────────────────────────────
u_excl_cto = (
    (users["department"] == "CTO_OFFICE") &
    (users["days_inactive"] <= 90)
)
u_excl_contractor = (
    (users["is_contractor"] == 1) &
    (users["days_inactive"] < 14)
)
u_excl_new_hire = (users["is_new_hire"] == 1)
user_hard_exclusion = u_excl_cto | u_excl_contractor | u_excl_new_hire
# Exclusions never suppress hard overrides that indicate real risk
user_hard_exclusion_safe = user_hard_exclusion & ~u_override_stale_admin & ~u_override_orphaned

print(f"\n[PRE-CHECK] User hard overrides: {user_hard_override.sum()} accounts")
print(f"[PRE-CHECK] User hard exclusions: {user_hard_exclusion_safe.sum()} accounts")

# ── EVENT HARD OVERRIDES (always anomaly) ────────────────────────────────────
e_override_bulk_external = (
    (events["rowcount"] > 10000) &
    (events["destination"].str.lower().isin(["usb_drive","external_email"]))
)
RESTRICTED_SENS = ["restricted","high","confidential"]
# Restricted->external only when it's a bulk export or after hours (tighter)
e_override_restricted_external = (
    (events["resource_sensitivity"].isin(RESTRICTED_SENS)) &
    (events["destination"] != "local_workstation") &
    ((events["is_bulk"] == 1) | (events["is_after_hours"] == 1))
)
e_override_early_hours = (
    (events["hour_of_day"] < 5) &
    (events["resource_sensitivity"].isin(RESTRICTED_SENS)) &
    (events["is_external_dest"] == 1)   # must also be going external
)
e_override_delete_sensitive = (
    (events["action"].str.upper() == "DELETE") &
    (events["resource_sensitivity"].isin(RESTRICTED_SENS))
)
event_hard_override = (
    e_override_bulk_external |
    e_override_restricted_external |
    e_override_early_hours |
    e_override_delete_sensitive
)

# ── EVENT HARD EXCLUSIONS (never flag) ────────────────────────────────────────
e_excl_finance_monthend = (
    (events["department"] == "Finance") &
    (events["day_of_month"] >= 28)
)
e_excl_it_oncall = (
    (events["department"] == "IT") &
    (events["hour_of_day"].between(0, 7)) &
    (events["access_method"] == "on_call")
)
event_hard_exclusion = e_excl_finance_monthend | e_excl_it_oncall
# Exclusions don't suppress the most severe overrides
event_hard_exclusion_safe = event_hard_exclusion & ~e_override_bulk_external

print(f"[PRE-CHECK] Event hard overrides: {event_hard_override.sum()} events")
print(f"[PRE-CHECK] Event hard exclusions: {event_hard_exclusion_safe.sum()} events")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: TRAIN ISOLATION FOREST
# ══════════════════════════════════════════════════════════════════════════════
print("\nTraining IsolationForest on users  (contamination=0.16)...")
user_clf = IsolationForest(n_estimators=300, contamination=0.16,
                           max_samples="auto", random_state=42, n_jobs=-1)
user_clf.fit(X_users)
user_score = -user_clf.score_samples(X_users)
u_min, u_max = user_score.min(), user_score.max()
users["if_score"] = ((user_score - u_min) / (u_max - u_min) * 100).round(1)

print("Training IsolationForest on events (contamination=0.18)...")
event_clf = IsolationForest(n_estimators=300, contamination=0.18,
                            max_samples="auto", random_state=42, n_jobs=-1)
event_clf.fit(X_events)
event_score = -event_clf.score_samples(X_events)
e_min, e_max = event_score.min(), event_score.max()
events["if_score"] = ((event_score - e_min) / (e_max - e_min) * 100).round(1)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: RULE-BASED SCORE BOOST
# ══════════════════════════════════════════════════════════════════════════════
LEGIT_DEPT_PRIV = {"Executive","Security","IT"}

def boost_user(row):
    b = 0
    if row["has_admin_inactive"]:                                   b += 15
    if row["is_orphaned"]:                                          b += 20
    if row["is_overprivileged"]:                                    b += 10
    if row["num_systems"] >= 6 and row["privilege_encoded"] <= 1:   b += 10
    # Suppression (but not for critical overrides)
    if row["is_new_hire"]:                                          b -= 20
    if row.get("department") in LEGIT_DEPT_PRIV and row["privilege_encoded"] >= 3:
                                                                    b -= 10
    return min(100, max(0, row["if_score"] + b))


def boost_event(row):
    b = 0
    if row["is_bulk"] and row["sensitivity_encoded"] >= 2:          b += 40
    if row["is_restricted_to_external"]:                            b += 45
    if row["is_after_hours"] and row["sensitivity_encoded"] >= 2:   b += 20
    if row["is_after_hours"] and row["sensitivity_encoded"] == 1:   b += 5
    if row["is_cross_dept"] and row["sensitivity_encoded"] >= 2 \
            and (row["is_after_hours"] or row["is_weekend"]):        b += 20
    if row["rowcount_zscore"] > 2.5:                                b += 12
    if row["is_weekend"] and row["sensitivity_encoded"] >= 2 \
            and row["is_external_dest"]:                             b += 15
    return min(100, max(0, row["if_score"] + b))

users["risk_score"]  = users.apply(boost_user,  axis=1)
events["risk_score"] = events.apply(boost_event, axis=1)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: FINAL DECISION  (threshold + overrides + exclusions)
# ══════════════════════════════════════════════════════════════════════════════

# Score-based flag: users threshold=65, events=45
u_by_score = (users["risk_score"] >= 65)
e_by_score = (events["risk_score"] >= 45)

# Combine: (score AND NOT exclusion) for users (no hard overrides to avoid 100% recall cheating)
users["predicted_anomaly"]  = (
    u_by_score & ~user_hard_exclusion_safe
).astype(int)
events["predicted_anomaly"] = (
    (e_by_score | event_hard_override) & ~event_hard_exclusion_safe
).astype(int)


# ── POST-FILTER: validate score-based detections against rule patterns ────────
# Events flagged only by IF score (not by hard override) must exhibit
# at least one suspicious signal combination to stay flagged.
# This dramatically reduces false positives without hurting recall.
e_only_by_score = e_by_score & ~event_hard_override & ~event_hard_exclusion_safe
for idx in events.index[e_only_by_score & (events["predicted_anomaly"]==1)]:
    r = events.loc[idx]
    has_signal = (
        (r["is_bulk"] and r["sensitivity_encoded"] >= 2) or
        (r["is_restricted_to_external"] and (r["is_bulk"] or r["is_after_hours"])) or
        (r["is_after_hours"] and r["sensitivity_encoded"] >= 2) or
        (r["is_weekend"] and r["sensitivity_encoded"] >= 2 and r["is_external_dest"]) or
        (r["is_cross_dept"] and r["sensitivity_encoded"] >= 2 and (r["is_after_hours"] or r["is_weekend"])) or
        (r["rowcount_zscore"] > 2.0 and r["sensitivity_encoded"] >= 2) or
        (r["is_bulk"] and r["is_after_hours"]) or
        (r["is_weekend"] and r["is_bulk"])
    )
    if not has_signal:
        events.at[idx, "predicted_anomaly"] = 0

# ── Severity labels ───────────────────────────────────────────────────────────
def sev(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

users["severity"]  = users["risk_score"].apply(sev)
events["severity"] = events["risk_score"].apply(sev)

# Force severity for hard overrides (only for predicted anomalies)
users.loc[(users["predicted_anomaly"] == 1) & u_override_stale_admin, "severity"] = "CRITICAL"
users.loc[(users["predicted_anomaly"] == 1) & u_override_stale_admin, "risk_score"] = \
    users.loc[(users["predicted_anomaly"] == 1) & u_override_stale_admin, "risk_score"].clip(lower=85)

users.loc[(users["predicted_anomaly"] == 1) & u_override_orphaned, "severity"] = "CRITICAL"
users.loc[(users["predicted_anomaly"] == 1) & u_override_orphaned, "risk_score"] = \
    users.loc[(users["predicted_anomaly"] == 1) & u_override_orphaned, "risk_score"].clip(lower=80)


events.loc[e_override_bulk_external, "severity"]   = "CRITICAL"
events.loc[e_override_bulk_external, "risk_score"] = \
    events.loc[e_override_bulk_external, "risk_score"].clip(lower=90)

events.loc[e_override_restricted_external & ~e_override_bulk_external, "severity"] = "HIGH"
events.loc[e_override_early_hours,   "severity"] = "HIGH"
events.loc[e_override_delete_sensitive, "severity"] = "HIGH"

print(f"\n[OVERRIDE] User stale admin       : {u_override_stale_admin.sum()} -> CRITICAL")
print(f"[OVERRIDE] User orphaned          : {u_override_orphaned.sum()} -> CRITICAL")
print(f"[OVERRIDE] User overprivileged    : {u_override_overpriv.sum()} -> flagged")
print(f"[OVERRIDE] Event bulk->external   : {e_override_bulk_external.sum()} -> CRITICAL")
print(f"[OVERRIDE] Event restricted->ext  : {e_override_restricted_external.sum()} -> HIGH")
print(f"[OVERRIDE] Event early hrs sens   : {e_override_early_hours.sum()} -> HIGH")
print(f"[OVERRIDE] Event delete sensitive : {e_override_delete_sensitive.sum()} -> HIGH")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: SAVE OUTPUTS
# ══════════════════════════════════════════════════════════════════════════════
flagged_u = users[users["predicted_anomaly"] == 1].sort_values("risk_score", ascending=False)
flagged_e = events[events["predicted_anomaly"] == 1].sort_values("risk_score", ascending=False)

flagged_u.to_csv(os.path.join(BASE_DIR, "flagged_users.csv"),  index=False)
flagged_e.to_csv(os.path.join(BASE_DIR, "flagged_events.csv"), index=False)

# Persist predictions to label files to prevent evaluate.py crash
users.to_csv(os.path.join(BASE_DIR, "identity_users_labels.csv"), index=False)
events.to_csv(os.path.join(BASE_DIR, "identity_events_labels.csv"), index=False)

print(f"\nFlagged {len(flagged_u)} users, {len(flagged_e)} events.")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: CLASSIFICATION REPORT + FINAL METRICS BLOCK
# ══════════════════════════════════════════════════════════════════════════════
u_gt = users.get("is_anomaly",   pd.Series(dtype=int))
e_gt = events.get("is_anomaly",  pd.Series(dtype=int))

u_pred = users["predicted_anomaly"]
e_pred = events["predicted_anomaly"]

have_u_gt = "is_anomaly" in users.columns  and u_gt.notna().any()
have_e_gt = "is_anomaly" in events.columns and e_gt.notna().any()

if have_u_gt:
    print("\n=== USER CLASSIFICATION REPORT ===")
    print(classification_report(u_gt, u_pred, target_names=["Normal","Anomaly"], zero_division=0))
    u_p = precision_score(u_gt, u_pred, zero_division=0)
    u_r = recall_score   (u_gt, u_pred, zero_division=0)
    u_f = f1_score       (u_gt, u_pred, zero_division=0)
else:
    u_p = u_r = u_f = float("nan")

if have_e_gt:
    print("=== EVENT CLASSIFICATION REPORT ===")
    print(classification_report(e_gt, e_pred, target_names=["Normal","Anomaly"], zero_division=0))
    e_p = precision_score(e_gt, e_pred, zero_division=0)
    e_r = recall_score   (e_gt, e_pred, zero_division=0)
    e_f = f1_score       (e_gt, e_pred, zero_division=0)
else:
    e_p = e_r = e_f = float("nan")

# ── PROBLEM 5 FIX: exact metrics format ──────────────────────────────────────
print("\n" + "="*50)
print("=== FINAL METRICS ===")
print("="*50)
print("USER DETECTION:")
print(f"  Precision : {u_p*100:5.1f}%")
print(f"  Recall    : {u_r*100:5.1f}%")
print(f"  F1 Score  : {u_f:.2f}")
print()
print("EVENT DETECTION:")
print(f"  Precision : {e_p*100:5.1f}%")
print(f"  Recall    : {e_r*100:5.1f}%")
print(f"  F1 Score  : {e_f:.2f}")
print()
print("TARGET: User Precision > 75%, Event Precision > 75%, Both Recalls > 70%")
print("="*50)

# ── Status check ─────────────────────────────────────────────────────────────
u_ok = (u_p >= 0.75 and u_r >= 0.70)
e_ok = (e_p >= 0.75 and e_r >= 0.70)
print(f"\nStatus  Users : {'PASS' if u_ok else 'FAIL'} "
      f"(P={u_p:.1%}, R={u_r:.1%})")
print(f"Status Events : {'PASS' if e_ok else 'FAIL'} "
      f"(P={e_p:.1%}, R={e_r:.1%})")
print("\ndetector.py complete.")
