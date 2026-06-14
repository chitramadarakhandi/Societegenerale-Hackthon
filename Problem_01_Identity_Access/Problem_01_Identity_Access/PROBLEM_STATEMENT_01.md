#  Problem Statement 01: Identity Sprawl & Privilege Abuse Detection

> **Enterprise Challenge:** Hybrid identity environments create identity sprawl—stale users, excessive privileges, orphaned service accounts. Modern breaches exploit identity weaknesses 80% more than malware.

---

## The Business Problem

**Scenario:** A global enterprise manages identities across 15+ systems:
- On-premise Active Directory (legacy apps)
- Azure AD (Microsoft 365, cloud apps)
- AWS IAM, GCP, Okta, Salesforce, ServiceNow
- Custom APIs and third-party integrations

**The Pain Points:**
-  **Manual Reviews:** Security team manually reviews 500+ access requests monthly
- ⏱ **Slow Time-to-Discovery:** Privilege abuse goes undetected for weeks
-  **Inconsistent Policies:** Different identity rules across systems
-  **Stale Accounts:** 15% of accounts are inactive but still privileged
-  **Alert Fatigue:** Too many false positives to act on

**Real Impact:**
- **Risk:** Compromised admin account could access financial data, HR systems, customer databases
- **Compliance:** NIST AC-2 (Account Management) violations; GDPR Article 32 (Security Measures)
- **Operational Cost:** 20 hours/week spent investigating access issues

---

## Challenge Overview

Build an automated system to:
1. **Detect** risky privilege patterns across hybrid identity platforms
2. **Classify** accounts by risk level (stale, over-privileged, orphaned)
3. **Prioritize** investigation with actionable insights
4. **Recommend** least-privilege remediation actions

---

##  Data Reality & Edge Cases (Making it Complex)

Your LLM-built solution must handle real-world messiness:

**Data Quality Issues:**
- Missing/incomplete data (95% of records have `last_login`, but 5% are null)
- Inconsistent timestamps (timezones vary, some in UTC, some in local time)
- Privilege datasets from different systems (no unified schema)
- Stale data (some user records updated monthly, others yearly)
- Service accounts with no activity baseline ("Should they be active?")

**Context Complexity:**
- Role-based exceptions (admin needs broad access for their job, not a risk)
- Temporary privilege escalations (on-call engineer with elevated access 1 week/month)
- Contractors vs employees (different activity patterns expected)
- Job changes (new hire might have unusual access for first 30 days)
- Seasonal patterns (Finance team more active month-end/quarter-end)

**Ambiguous Scenarios:**
- User A: Admin account with 60 days inactivity (fire immediately or check if on sabbatical?)
- User B: Service account with unusual access pattern (legitimate automation or compromised?)
- User C: Accessed 50 systems yesterday (role change or privilege escalation?)
- User D: Downloaded 100k records at 2 AM (suspicious or legitimate batch job?)

**The Challenge:**
Your LLM/solution must:**
- **Disambiguate** between risky and legitimate patterns
- **Reduce false positives** (or security team stops trusting it)
- **Explain reasoning** (why is this account risky? technical team needs to understand)
- **Handle context** (not just "flag all unusual" but "flag suspicious + explain")

---

##  Approach Options

### Option A: AI/ML-Powered Risk Scoring (Advanced)
**Best for:** Teams with ML experience, data science background

**Technical Approach:**
- Ingest identity/audit logs from multiple sources (API integrations)
- Train behavior model: "What does normal activity look like for this role?"
- Use anomaly detection (Isolation Forest, Autoencoders) to flag deviations
- LLM-assisted: Generate human-readable risk narratives
- Output: Risk dashboard with confidence scores and recommended actions

**Skills Required:** Python, ML (scikit-learn, TensorFlow), SQL, LLM APIs
**Complexity:**  (4/5)
**Effort:** 30-40 hours

---

### Option B: Rule-Based & Graph Analysis (Intermediate)
**Best for:** Teams with backend/data engineering skills

**Technical Approach:**
- Build privilege graph: Users → Roles → Systems → Resources
- Define rule engine: "Privilege exceeds role requirements"
- Correlate with activity logs: "No activity in 90 days = stale"
- Use graph analysis (NetworkX) to find isolated privilege clusters
- Output: Risk report with visual privilege maps

**Skills Required:** Python, Graph databases/NetworkX, SQL, basic analytics
**Complexity:**  (3/5)
**Effort:** 20-30 hours

---

### Option C: Process Automation & Alerting (Beginner-Intermediate)
**Best for:** Teams with full-stack/DevOps experience

**Technical Approach:**
- Connect identity system APIs (Okta, Azure AD, AWS IAM)
- Extract privilege & activity data nightly
- Apply heuristic rules (e.g., "Flag unused admin accounts")
- Build notification system (alerts to Slack/email)
- Create simple dashboard (Google Sheets API or web interface)
- Output: Automated alerts + weekly summary report

**Skills Required:** Python, REST APIs, basic web (Flask/FastAPI), automation
**Complexity:**  (2/5)
**Effort:** 15-25 hours

---

##  Example Walkthrough: From Data to Insight

**Input: Raw Data Row**
```csv
user_id,username,email,department,privilege_level,systems_access,last_login,days_inactive,is_active,hire_date,role_title
USR028,bella.green,bella.green@company.com,CTO_OFFICE,admin,"PROD-DB,PROD-APP,ADMIN-CONSOLE,ALL-LOGS,SIEM",2026-04-01,19,false,2009-01-15,Chief Technology Officer
```

**Expected Output by Your System:**
```json
{
  "user_id": "USR028",
  "username": "bella.green",
  "risk_level": "CRITICAL",
  "risk_score": 92,
  "findings": [
    {
      "finding": "STALE_PRIVILEGED_ACCOUNT",
      "details": "Admin account inactive for 19 days with access to production systems",
      "severity": "HIGH",
      "recommendation": "Review termination status or reactivate"
    },
    {
      "finding": "BROAD_PRIVILEGE_SCOPE",
      "details": "Admin has access to 5 critical systems including PROD-DB and SIEM",
      "severity": "MEDIUM",
      "recommendation": "Audit if all access is necessary for current role"
    },
    {
      "finding": "CTO_ROLE_EXCEPTION",
      "details": "CTO_OFFICE accounts typically have broad access; flag only if policy changed",
      "severity": "INFORMATIONAL",
      "recommendation": "Verify with HR if still employed"
    }
  ],
  "confidence": 0.87,
  "suggested_actions": [
    "Confirm employment status with HR",
    "If no longer employed, revoke all access immediately",
    "If employed, investigate why inactive for 19 days"
  ],
  "next_escalation": "Security manager review required"
}
```

**Why This Matters:**
- Score alone (92/100) isn't enough → **context and explanation are critical**
- Exception recognition (CTO role) → Shows your system understands **nuance**
- Recommendations are **actionable** → Not just "flag it", but "here's what to do"
- Confidence score → Shows your system's **certainty level**

---

## Sample Data Provided

**Files in `sample_data/`:**

| File | Records | Coverage | Description |
|------|---------|----------|-------------|
| `identity_users.csv` | 300 | Current snapshot | User accounts, privilege levels, last login, department |
| `identity_events.csv` | 900 | Full 365 days (Apr 2025 – Apr 2026) | Access events with timestamps, resource, sensitivity |
| `identity_users_labels.csv` | 300 | All users | Ground truth: is_anomaly, anomaly_type, severity, explanation |
| `identity_events_labels.csv` | 900 | All events | Ground truth: is_anomaly, anomaly_type, severity, explanation |

**Anomaly distribution in labels:**
- User anomalies: ~16% (stale admins, over-privileged accounts)
- Event anomalies: ~41% (after-hours, bulk export, cross-department)

**Self-Evaluation (run this to check your precision/recall):**
```python
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

# Load your predictions vs ground truth
labels = pd.read_csv('identity_events_labels.csv')
# Assuming your solution adds a column 'predicted_anomaly' (True/False)
# labels['predicted_anomaly'] = your_model.predict(events)

y_true = labels['is_anomaly'].astype(int)
y_pred = labels['predicted_anomaly'].astype(int)  # your output

print(f"Precision: {precision_score(y_true, y_pred):.2%}")
print(f"Recall:    {recall_score(y_true, y_pred):.2%}")
print(f"F1 Score:  {f1_score(y_true, y_pred):.2f}")
```

**Data span note:** Events cover a full year — include month-end finance spikes, quarterly patterns, seasonal access shifts. Baselines built only on short windows will produce more false positives.

---

##  Detailed Evaluation Rubric

**Total Score: 100 points**

### 1. **Detection Quality (30 points)**
- **Precision (15 pts):** % of flagged accounts that are actually risky
  - 85-100%: 15 pts | 70-84%: 12 pts | 55-69%: 9 pts | <55%: 0 pts
- **Recall (10 pts):** % of actual risks that are detected
  - 80-100%: 10 pts | 65-79%: 8 pts | 50-64%: 5 pts | <50%: 0 pts
- **F1-Score consistency (5 pts):** Balanced precision/recall
  - >0.75: 5 pts | 0.6-0.75: 3 pts | <0.6: 0 pts

### 2. **Explainability & Narrative (25 points)**
- **LLM-Generated Explanations (15 pts):**
  - Clear, non-technical narrative explaining WHY account is risky
  - 90-100% narratives >100 chars: 15 pts | 70-89%: 12 pts | <70%: 0 pts
- **Context Awareness (10 pts):**
  - System recognizes exceptional cases (CTO admin, new hire, on-call, etc.)
  - Excellent discrimination: 10 pts | Good: 7 pts | Minimal: 3 pts | None: 0 pts

### 3. **Actionability (20 points)**
- **Remediation Recommendations (12 pts):**
  - Specific, executable next steps for each risk
  - All findings have clear actions: 12 pts | 75%: 9 pts | 50%: 6 pts | <50%: 0 pts
- **Risk Prioritization (8 pts):**
  - Top 10 risks should represent highest business impact
  - Excellent prioritization: 8 pts | Good: 5 pts | Fair: 2 pts | Poor: 0 pts

### 4. **Code Quality & Performance (15 points)**
- **Runtime Performance (8 pts):**
  - <5 sec for full analysis: 8 pts | 5-15 sec: 6 pts | 15-30 sec: 3 pts | >30 sec: 0 pts
- **Documentation & Reproducibility (7 pts):**
  - Clear code, comments, README, usage instructions
  - Excellent docs: 7 pts | Good: 5 pts | Fair: 3 pts | Poor: 0 pts

### 5. **Bonus Points (Up to 10 extra)**
- **Real-time Dashboard:** Interactive web UI showing flagged users (+5 pts)
- **Anomaly Visualization:** Graph showing privilege sprawl (+3 pts)
- **API Integration:** Mock API to real identity systems (+3 pts)
- **Exception Handling:** System gracefully handles missing/malformed data (+2 pts)
- **Presentation Quality:** Clear 5-min demo with visuals (+2 pts)

**Scoring Examples:**
- **Conservative Approach** (Rule-based): 40-60 points (good precision, lower recall)
- **Balanced Approach** (Heuristics + ML): 60-75 points (good both)
- **Advanced Approach** (LLM + ML + Context): 75-90 points (if well-executed)

---

##  Explicit Deliverables Checklist

All teams MUST submit these items (missing any = automatic points deduction):

- [ ] **Code Repository** (GitHub/GitLab)
  - Clear structure: `src/`, `models/`, `notebooks/`, `README.md`
  - All code must run: `python solution.py < data/ > output.json`
  - Requirements file: `pip install -r requirements.txt`

- [ ] **Jupyter Notebook** (Exploratory Analysis)
  - Data loading, visualization, insights discovered
  - Ground truth labels analysis (what anomalies exist?)
  - 15-20 mins to run

- [ ] **Risk Dashboard** (Minimum: CLI output, Better: web UI)
  - Option A: Interactive web dashboard (localhost:5000)
  - Option B: Beautiful CLI with colored output
  - Shows: Top 20 risks, sorted by risk level, with explanations

- [ ] **Sample Output Report** (JSON or CSV)
  - At least 20 flagged accounts with full reasoning
  - Format:
    ```json
    {
      "findings": [
        {"user_id": "USR028", "risk_score": 92, "reason": "...", "actions": [...]}
      ],
      "metadata": {"total_users": 100, "risks_detected": 20, "avg_precision": 0.87}
    }
    ```

- [ ] **Technical Documentation** (README or slides)
  - Approach used (Option A/B/C modified how?)
  - Data quality challenges encountered & solutions
  - Key assumptions & limitations
  - How to scale to 10k+ users?

- [ ] **5-Minute Presentation** (slides or demo)
  - Problem explained in 60 seconds
  - Solution architecture (diagram)
  - 2-3 example risks with clear explanations
  - Q&A ready

---

##  Recommended Timeline (48-72 hours)

**Day 1 (Hours 0-12):**
- Hours 0-2: Read problem statement + sample data
- Hours 2-4: Explore data (Jupyter notebook)
- Hours 4-6: Understand ground truth (what are labeled anomalies?)
- Hours 6-8: Decide on approach (A/B/C) + rough plan
- Hours 8-12: Implement core logic (get something working first)

**Day 1 Evening (Hours 12-20):**
- Hours 12-14: Evaluate first pass against ground truth
- Hours 14-18: Refine logic, fix false positives
- Hours 18-20: Add LLM explanations

**Day 2 (Hours 20-36):**
- Hours 20-24: Build dashboard / CLI output
- Hours 24-28: Write documentation
- Hours 28-32: Create sample report with best findings
- Hours 32-36: Prepare presentation

**Day 3 (Hours 36-48):** (Optional, if 72-hour hackathon)
- Hours 36-40: Polish dashboard, add visualizations
- Hours 40-44: Bonus features (API, advanced analytics)
- Hours 44-48: Final testing & presentation rehearsal

---

##  Bonus Features (Challenge Yourself!)

** Level 1: Implementation Bonus (5 pts each)**
- Real-time alert dashboard (web UI, updates live)
- Privilege graph visualization (NetworkX → interactive)
- Automated remediation playbook (step-by-step fix)
- Multi-system correlation (link related risks across systems)

** Level 2: Advanced Intelligence (10 pts each)**
- Behavioral clustering (group similar risky patterns)
- Breach impact simulation ("if this account compromised, what's at risk?")
- False positive feedback loop (system learns to adjust based on corrections)
- Integration with real Okta/Azure AD APIs

** Level 3: Enterprise Features (15 pts each)**
- Organizational anomaly detection (unusual access patterns at dept level)
- Separation of duties violations (role conflicts detected)
- Compliance gap analysis (per user, per system)
- DLP integration (prevent exfiltration based on detected risk)

---

##  FAQ

**Q: Can we use external LLM APIs (ChatGPT, Claude)?**
A: Yes! If you do: (1) document all API calls, (2) show cost estimates, (3) have fallback without LLM.

**Q: What if our precision/recall don't hit targets?**
A: No problem! Judges reward transparent trade-offs. Just explain: "We optimized for precision to reduce alert fatigue."

**Q: Can we use pre-built models/libraries?**
A: Yes! Use scikit-learn, TensorFlow, Hugging Face, etc. Just cite them and explain customizations.

**Q: What if the data is too small/large?**
A: (100K rows is manageable). If too large, sample. If too small, explain assumptions.

**Q: Can we work with people from other companies?**
A: Yes, this is an individual contest but cross-company teams encouraged.

**Q: Do we need a working dashboard?**
A: No, but it significantly improves presentation/scoring. Even CLI with colors works.

**Q: What if we find data quality issues?**
A: Great! Document them: "Found 5% missing values in `last_login`. Handled by: [your approach]"

---

##  Judge Evaluation Guide (Internal)

**For Judges Scoring Submissions:**

**Green Flag Indicators (High-Quality):**
-  LLM-generated explanations are specific & non-generic
-  System catches both obvious (stale account) & subtle (context-dependent) risks
-  False positives are minimal; team can explain why each flag matters
-  Dashboard is intuitive; non-technical users could understand findings
-  Team can articulate trade-offs (precision vs recall, speed vs accuracy)

**Red Flag Indicators (Low-Quality):**
-  Generic explanations ("Account flagged because inactive")
-  Precision <50% (too many false alarms)
-  No distinction between admin/contractor/regular user (ignores context)
-  Dashboard is confusing or missing
-  Can't explain why certain accounts are flagged

**Questions for Teams:**
1. "Walk us through one flagged account. Why is it risky?"
2. "How did you handle the stale admin account (know he's CTO, on sabbatical)?"
3. "What's your biggest limitation & how would you fix it?"
4. "How would this scale to 100k users?"
5. "Show us a false positive. Why did your system flag it?"

**Scoring Guideline:**
- **Top Tier (80-100):** Excellent explainability, low false positives, impressive UI
- **Mid Tier (60-79):** Good detection, decent explainability, functional demo
- **Lower Tier (40-59):** Works but limited context awareness or high false positives
- **Below 40:** Missing key components or doesn't actually detect meaningful risks

---


