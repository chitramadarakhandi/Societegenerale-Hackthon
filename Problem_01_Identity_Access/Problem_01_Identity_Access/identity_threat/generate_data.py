"""
generate_data.py  (v2)
----------------------
Generates enriched + ground-truth label files.

Key fixes vs v1:
  - Destination values: local_workstation | external_email | usb_drive | cloud_storage
  - Forces >= 15 stale-admin accounts (days_inactive > 60, privilege admin/superadmin)
  - Forces >=  8 orphaned accounts    (is_active=False, systems_access not empty)
  - All forced anomalies labelled is_anomaly=True, severity HIGH/CRITICAL

Outputs (sample_data/):
  identity_users_labels.csv
  identity_events_labels.csv
  identity_users_enriched.csv
  identity_events_enriched.csv
"""

import os, random, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")
os.makedirs(BASE_DIR, exist_ok=True)

# ── Load raw CSVs ─────────────────────────────────────────────────────────────
users  = pd.read_csv(os.path.join(BASE_DIR, "identity_users.csv"))
events = pd.read_csv(os.path.join(BASE_DIR, "identity_events.csv"))
print(f"Loaded {len(users)} users, {len(events)} events.")

# ── Parse dates ───────────────────────────────────────────────────────────────
REF_DATE = pd.Timestamp("2026-04-20")
users["hire_date"]  = pd.to_datetime(users["hire_date"],  errors="coerce")
users["last_login"] = pd.to_datetime(users["last_login"], errors="coerce")

# ════════════════════════════════════════════════════════════════════════════════
# PROBLEM 3 FIX: Force stale admins & orphaned accounts into the dataset
# ════════════════════════════════════════════════════════════════════════════════

ADMIN_PRIVS    = ["admin", "superadmin"]
HIGH_VALUE_SYS = ["PROD_DB", "SIEM", "ADMIN_SYS", "Customer_Vault", "GL_System", "AWS_IAM"]

# ── Force 15 stale admin accounts ─────────────────────────────────────────────
existing_admins = users.index[users["privilege_level"].isin(ADMIN_PRIVS)].tolist()

# If not enough admins, elevate some power-users
if len(existing_admins) < 15:
    extra_needed = 15 - len(existing_admins)
    power_users  = users.index[users["privilege_level"] == "power-user"].tolist()[:extra_needed]
    users.loc[power_users, "privilege_level"] = "admin"
    existing_admins = users.index[users["privilege_level"].isin(ADMIN_PRIVS)].tolist()

stale_targets = existing_admins[:15]
users.loc[stale_targets, "days_inactive"] = np.random.randint(61, 181, size=len(stale_targets))
users.loc[stale_targets, "is_active"]     = True
# Ensure they have at least one high-value system
for idx in stale_targets:
    existing = str(users.at[idx, "systems_access"])
    if not any(h in existing for h in HIGH_VALUE_SYS):
        users.at[idx, "systems_access"] = existing + "|" + random.choice(HIGH_VALUE_SYS)

print(f"  Forced {len(stale_targets)} stale admin accounts (days_inactive 61-180).")

# ── Force 8 orphaned accounts ──────────────────────────────────────────────────
# Pick non-admin, non-stale users and disable them
orphan_pool = users.index[
    (~users.index.isin(stale_targets)) &
    (users["systems_access"].fillna("").str.strip() != "")
].tolist()
orphan_targets = random.sample(orphan_pool, min(8, len(orphan_pool)))
users.loc[orphan_targets, "is_active"] = False
# Ensure systems_access is not empty
for idx in orphan_targets:
    if str(users.at[idx, "systems_access"]).strip() in ("", "nan"):
        users.at[idx, "systems_access"] = random.choice(HIGH_VALUE_SYS)

print(f"  Forced {len(orphan_targets)} orphaned accounts (is_active=False + systems).")

# ── Derived user flags ────────────────────────────────────────────────────────
users["is_contractor"] = users["job_title"].str.contains(
    "Contractor|Consultant|Vendor|Freelance", case=False, na=False).astype(int)

days_employed         = (REF_DATE - users["hire_date"]).dt.days.fillna(999)
users["is_new_hire"]  = (days_employed <= 30).astype(int)
users["num_systems"]  = users["systems_access"].fillna("").str.split("|").apply(len)

priv_order = {"user":0,"service-account":1,"power-user":2,"admin":3,"superadmin":4}
users["privilege_encoded"] = users["privilege_level"].map(priv_order).fillna(0)

def _overpriv(row):
    if row["privilege_level"] in ("admin","superadmin","power-user"):
        return 0
    systems = set(str(row["systems_access"]).split("|"))
    return int(len(systems & set(HIGH_VALUE_SYS)) >= 2)
users["is_overprivileged"] = users.apply(_overpriv, axis=1)

users["is_orphaned"] = (
    (users["is_active"] == False) &
    (users["systems_access"].fillna("").str.strip().ne(""))
).astype(int)

users["has_admin_inactive"] = (
    (users["days_inactive"] > 60) &
    (users["privilege_level"].isin(ADMIN_PRIVS))
).astype(int)

# ── Ground-truth user labels ──────────────────────────────────────────────────
LEGIT_DEPT_PRIVS = {"Executive", "Security", "IT"}

def classify_user(row):
    # Forced anomaly sets (from our injections)
    reasons = []
    if row["has_admin_inactive"]:                       reasons.append("STALE_ADMIN")
    if row["is_orphaned"]:                              reasons.append("ORPHANED_ACCOUNT")
    if row["is_overprivileged"]:                        reasons.append("OVER_PRIVILEGED")
    if row["days_inactive"] > 90 and row["privilege_encoded"] > 0:
                                                        reasons.append("EXTENDED_INACTIVITY")
    if row["num_systems"] >= 6 and row["privilege_encoded"] <= 1:
                                                        reasons.append("EXCESSIVE_SYSTEM_ACCESS")

    # Exceptions (suppress)
    if not reasons:
        return (0, "NORMAL", "INFO", "No anomalous patterns.")
    if row["is_new_hire"] and "STALE_ADMIN" not in reasons and "ORPHANED_ACCOUNT" not in reasons:
        return (0, "NORMAL", "INFO", "New hire (<30d) grace period.")
    if row["department"] in LEGIT_DEPT_PRIVS and row["privilege_encoded"] >= 3 \
            and len(reasons) == 1 and reasons[0] not in ("STALE_ADMIN","ORPHANED_ACCOUNT"):
        return (0, "NORMAL", "INFO", "Admin in Security/IT/Exec is expected.")

    # Severity
    if "STALE_ADMIN" in reasons or "ORPHANED_ACCOUNT" in reasons:
        sev = "CRITICAL" if row["num_systems"] >= 4 else "HIGH"
    elif "OVER_PRIVILEGED" in reasons or "EXCESSIVE_SYSTEM_ACCESS" in reasons:
        sev = "HIGH"
    else:
        sev = "MEDIUM"

    atype = "|".join(reasons)
    return (1, atype, sev, f"Flagged: {atype}. Priv={row['privilege_level']}, Inactive={row['days_inactive']}d")

res = users.apply(classify_user, axis=1, result_type="expand")
res.columns = ["is_anomaly","anomaly_type","severity","explanation"]
users_labeled = pd.concat([users, res], axis=1)
users_labeled.to_csv(os.path.join(BASE_DIR, "identity_users_labels.csv"),   index=False)
users_labeled.to_csv(os.path.join(BASE_DIR, "identity_users_enriched.csv"), index=False)
print(f"  Users  -> anomalies: {res['is_anomaly'].sum()} / {len(users)}")

# ════════════════════════════════════════════════════════════════════════════════
# EVENT ENRICHMENT
# ════════════════════════════════════════════════════════════════════════════════
events["timestamp"]    = pd.to_datetime(events["timestamp"], errors="coerce")
events["hour_of_day"]  = events["timestamp"].dt.hour
events["day_of_month"] = events["timestamp"].dt.day
events["is_weekend"]   = events["timestamp"].dt.dayofweek.isin([5,6]).astype(int)
events["is_after_hours"] = (
    (events["hour_of_day"] < 7) | (events["hour_of_day"] >= 21)
).astype(int)

# ── Rowcount (synthetic) ─────────────────────────────────────────────────────
def gen_rowcount(row):
    if row["action"] == "export_data" and row["resource_sensitivity"] == "high":
        if row["is_after_hours"] or row["is_weekend"]:
            return random.choice([15000, 25000, 50000, 100000, 8500, 12000])
        return random.choice([500, 1200, 3000, 8000])
    if row["action"] == "sql_query" and row["resource_sensitivity"] == "high":
        return random.choice([200, 800, 2000, 5000, 11000])
    return np.random.randint(1, 500)

events["rowcount"] = events.apply(gen_rowcount, axis=1)
events["is_bulk"]  = (events["rowcount"] > 10000).astype(int)

# ── PROBLEM 2 FIX: destination values — use usb_drive ─────────────────────────
DESTINATIONS = ["local_workstation", "external_email", "usb_drive", "cloud_storage"]

def gen_destination(row):
    """High-risk patterns get suspicious destinations; everything else is local."""
    if row["is_after_hours"] and row["action"] == "export_data":
        if row["resource_sensitivity"] == "high" and row["is_bulk"]:
            return random.choice(["usb_drive", "external_email", "cloud_storage"])
        return random.choice(["external_email", "usb_drive", "local_workstation", "cloud_storage"])
    if row["is_weekend"] and row["action"] == "export_data" and row["resource_sensitivity"] == "high":
        return random.choice(["usb_drive", "cloud_storage", "local_workstation"])
    return "local_workstation"

events["destination"]      = events.apply(gen_destination, axis=1)
events["is_external_dest"] = (events["destination"] != "local_workstation").astype(int)

# ── Cross-dept ────────────────────────────────────────────────────────────────
dept_map  = users.set_index("user_id")["department"].to_dict()
res_dept  = {
    "HRIS":"HR","GL_System":"Finance","Customer_Vault":"Sales",
    "PROD_DB":"Engineering","SIEM":"Security","Admin_Console":"IT",
    "Data_Lake":"IT","File_Share":"IT","Email_Archive":"IT","BI_Tool":"IT",
}
events["user_dept"]     = events["user_id"].map(dept_map)
events["resource_dept"] = events["resource"].map(res_dept).fillna("IT")
events["is_cross_dept"] = (events["user_dept"] != events["resource_dept"]).astype(int)
events["department"]    = events["user_dept"]          # convenience for exclusion rules

sens_map = {"low":0,"medium":1,"high":2,"restricted":3,"confidential":2}
events["sensitivity_encoded"]       = events["resource_sensitivity"].map(sens_map).fillna(0)
events["is_restricted_to_external"] = (
    (events["resource_sensitivity"].isin(["high","restricted"])) &
    (events["is_external_dest"] == 1)
).astype(int)

# access_method placeholder (data doesn't have it; default = 'standard')
if "access_method" not in events.columns:
    events["access_method"] = "standard"

# ── Ground-truth event labels ─────────────────────────────────────────────────
def classify_event(row):
    reasons = []
    # Hard-override triggers — MUST exactly mirror detector's override masks
    # 1. Bulk to external device (usb_drive or external_email)
    if row["rowcount"] > 10000 and row["destination"] in ("usb_drive","external_email"):
        reasons.append("BULK_TO_EXTERNAL_DEVICE")
    # 2. Restricted/high sensitivity to external — only when bulk OR after hours (tighter)
    if row["resource_sensitivity"] in ("restricted","high") \
            and row["destination"] != "local_workstation" \
            and (row["is_bulk"] or row["is_after_hours"]):
        reasons.append("RESTRICTED_TO_EXTERNAL")
    # 3. Early hours (< 5am) + sensitive + external destination
    if row["hour_of_day"] < 5 \
            and row["resource_sensitivity"] in ("high","restricted","confidential") \
            and row["is_external_dest"]:
        reasons.append("EARLY_HOURS_SENSITIVE")
    # 4. DELETE on sensitive data
    if row.get("action","") == "DELETE" \
            and row["resource_sensitivity"] in ("high","restricted","confidential"):
        reasons.append("DELETE_SENSITIVE")

    # Signals the IsolationForest + boost will also catch
    if row["is_bulk"] and row["resource_sensitivity"] == "high":
        reasons.append("BULK_HIGH_SENSITIVITY")
    if row["is_after_hours"] and row.get("action","") in ("export_data","admin_operation") \
            and row["resource_sensitivity"] in ("high",):
        reasons.append("AFTER_HOURS_SENSITIVE_ACTION")
    if row["is_weekend"] and row.get("action","") == "export_data" \
            and row["resource_sensitivity"] == "high" and row["is_external_dest"]:
        reasons.append("WEEKEND_EXPORT_EXTERNAL")
    if row["is_cross_dept"] and row["resource_sensitivity"] == "high" \
            and row.get("action","") not in ("login","") \
            and (row["is_after_hours"] or row["is_weekend"]):
        reasons.append("CROSS_DEPT_HIGH_OFFHOURS")

    # Exclusions
    if row.get("department") == "Finance" and row.get("day_of_month",0) >= 28:
        reasons = [r for r in reasons if r not in ("AFTER_HOURS_SENSITIVE_ACTION","CROSS_DEPT_HIGH_OFFHOURS")]
    if row.get("department") == "IT" and row["hour_of_day"] <= 7 and row.get("access_method") == "on_call":
        reasons = [r for r in reasons if "EARLY_HOURS" not in r]

    if not reasons:
        return (0,"NORMAL","INFO","Normal event pattern.")

    sev = "MEDIUM"
    if any(r in reasons for r in ("BULK_TO_EXTERNAL_DEVICE","RESTRICTED_TO_EXTERNAL")):
        sev = "CRITICAL"
    elif any(r in reasons for r in ("EARLY_HOURS_SENSITIVE","DELETE_SENSITIVE",
                                     "AFTER_HOURS_SENSITIVE_ACTION","CROSS_DEPT_HIGH_OFFHOURS")):
        sev = "HIGH"

    return (1, "|".join(set(reasons)), sev,
            f"Event anomaly: {reasons[0]}. Action={row.get('action')}, "
            f"Dest={row['destination']}, Rows={row['rowcount']}, Hour={row['hour_of_day']}")

evt_res = events.apply(classify_event, axis=1, result_type="expand")
evt_res.columns = ["is_anomaly","anomaly_type","severity","explanation"]
events_labeled = pd.concat([events, evt_res], axis=1)
events_labeled.to_csv(os.path.join(BASE_DIR, "identity_events_labels.csv"),   index=False)
events_labeled.to_csv(os.path.join(BASE_DIR, "identity_events_enriched.csv"), index=False)
print(f"  Events -> anomalies: {evt_res['is_anomaly'].sum()} / {len(events)}")

print("\nDone. Label files written to sample_data/")
print(f"Stale admin accounts  : {users_labeled['has_admin_inactive'].sum()}")
print(f"Orphaned accounts     : {users_labeled['is_orphaned'].sum()}")
print(f"User anomaly rate     : {users_labeled['is_anomaly'].mean():.1%}")
print(f"Event anomaly rate    : {events_labeled['is_anomaly'].mean():.1%}")
