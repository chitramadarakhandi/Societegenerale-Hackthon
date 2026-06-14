# Identity Threat Intelligence — Audit Report

## Executive Summary

| Metric | Users | Events |
|--------|-------|--------|
| Precision | 94.29% | 87.27% |
| Recall    | 94.29% | 82.76% |
| F1-Score  | 0.94   | 0.85   |

## Top 10 Flagged Users

### 1. USR00012 — vikram.white (Score: 100)
- **Severity:** CRITICAL
- **Department:** Operations | **Privilege:** service-account
- **Days Inactive:** 25 | **Systems:** 2
- **LLM Findings:**
  - `ORPHANED_ACCOUNT`: Account has been inactive for 25 days and is orphaned
  - `INACTIVE_SERVICE_ACCOUNT`: Service account has been inactive for 25 days
- **Blast Radius:** 10,000 records, GDPR: €20 million or 4% revenue

### 2. USR00058 — anthony.taylor (Score: 100)
- **Severity:** CRITICAL
- **Department:** Finance | **Privilege:** user
- **Days Inactive:** 51 | **Systems:** 1
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 51 days
  - `ORPHANED_ACCOUNT`: Account is orphaned, indicating a potential lack of ownership or oversight
- **Blast Radius:** 1,000 records, GDPR: €20 million or 4% revenue

### 3. USR00027 — pooja.sullivan (Score: 100)
- **Severity:** CRITICAL
- **Department:** Support | **Privilege:** admin
- **Days Inactive:** 112 | **Systems:** 7
- **LLM Findings:**
  - `INACTIVE_ADMIN`: Admin account inactive for 112 days
  - `EXCESSIVE_SYSTEM_ACCESS`: Access to 7 systems including sensitive areas like ADMIN_SYS and SIEM
- **Blast Radius:** 50,000 records, GDPR: €20 million or 4% revenue

### 4. USR00155 — varun.colombo (Score: 100)
- **Severity:** CRITICAL
- **Department:** Sales | **Privilege:** admin
- **Days Inactive:** 35 | **Systems:** 6
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 35 days
  - `ORPHANED_ACCOUNT`: Account is orphaned, indicating a potential lack of ownership or oversight
- **Blast Radius:** 10,000 records, GDPR: €10 million or 2% revenue

### 5. USR00063 — daniel.colombo (Score: 100)
- **Severity:** CRITICAL
- **Department:** Sales | **Privilege:** power-user
- **Days Inactive:** 52 | **Systems:** 2
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 52 days
  - `ORPHANED_ACCOUNT`: Account is orphaned with no clear ownership or departmental affiliation
- **Blast Radius:** 1,000 records, GDPR: €500,000 or 2% revenue

### 6. USR00078 — christopher.menon (Score: 100)
- **Severity:** CRITICAL
- **Department:** Executive | **Privilege:** service-account
- **Days Inactive:** 22 | **Systems:** 1
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 22 days
  - `ORPHANED_ACCOUNT`: Account is orphaned with no clear ownership or management
- **Blast Radius:** 1,000 records, GDPR: €20 million or 4% revenue

### 7. USR00140 — riya.lim (Score: 100)
- **Severity:** CRITICAL
- **Department:** Legal | **Privilege:** user
- **Days Inactive:** 35 | **Systems:** 2
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 35 days
  - `ORPHANED_ACCOUNT`: Account is orphaned, indicating a lack of ownership or oversight
- **Blast Radius:** 500 records, GDPR: €20 million or 4% revenue

### 8. USR00125 — kenneth.verma (Score: 100)
- **Severity:** CRITICAL
- **Department:** Marketing | **Privilege:** admin
- **Days Inactive:** 177 | **Systems:** 6
- **LLM Findings:**
  - `INACTIVE_ADMIN`: The admin account has been inactive for 177 days
  - `EXCESSIVE_PRIVILEGES`: The account has access to 6 systems, including SIEM, AWS_IAM, Azure_AD, EMAIL, Okta, and GCP
- **Blast Radius:** 100,000 records, GDPR: €20 million or 4% revenue

### 9. USR00294 — kenneth.colombo (Score: 99)
- **Severity:** CRITICAL
- **Department:** Executive | **Privilege:** user
- **Days Inactive:** 11 | **Systems:** 1
- **LLM Findings:**
  - `INACTIVE_ACCOUNT`: Account has been inactive for 11 days
  - `ORPHANED_ACCOUNT`: Account is orphaned, indicating a potential lack of ownership or oversight
- **Blast Radius:** 1,000 records, GDPR: €20 million or 4% revenue

### 10. USR00236 — harsh.connor (Score: 98)
- **Severity:** CRITICAL
- **Department:** Legal | **Privilege:** service-account
- **Days Inactive:** 40 | **Systems:** 2
- **LLM Findings:**
  - `OVERPRIVILEGED_ACCESS`: User has access to 2 systems (PROD_DB and ADMIN_SYS) with a service-account privilege level, despite being inactive for 40 days
  - `INACTIVE_ACCOUNT`: Account has been inactive for 40 days, which may indicate a potential security risk
- **Blast Radius:** 100,000 records, GDPR: €20 million or 4% revenue

## Compliance Impact

| Framework | Requirement | Violations Found |
|-----------|-------------|-----------------|
| NIST AC-2 | Account Management — disable inactive accounts | Stale admin accounts |
| GDPR Art. 32 | Technical security measures for data access | External data exports |
| SOX 302 | Controls over financial data access | Cross-dept GL_System access |

## Remediation Playbook

1. **Immediate (< 4 hours):** Disable all CRITICAL-severity accounts pending HR verification
2. **Short-term (< 24 hours):** Force password reset on all HIGH-severity accounts
3. **Medium-term (1 week):** Conduct access reviews for all power-user and admin accounts
4. **Long-term:** Implement automated quarterly access certifications

---
*Generated by Identity Threat Intelligence Platform*