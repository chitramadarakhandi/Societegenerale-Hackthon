# Problem 01: Identity Sprawl & Access Detection - Sample Datasets

## Overview
This folder contains sample/mock data for Problem Statement 01. All data is fabricated and represents a **sample** for development/testing purposes.

## Files Included

### 1. `identity_users.csv` (100 user records)
**Comprehensive mock user account database** with realistic attributes across multiple departments.

**Columns:**
- `user_id` - Unique identifier
- `username` - Login name
- `email` - Email address
- `department` - Which department (Finance, IT, HR, etc.)
- `job_title` - Role
- `privilege_level` - user, power-user, admin
- `systems_access` - Pipe-separated list of allowed systems
- `privileged_roles` - Admin-level roles if any
- `last_login` - When they last accessed anything
- `days_inactive` - How many days since last login
- `is_active` - Currently active employee?
- `hired_date` - When they joined
- `role_change_date` - When their role changed (if applicable)

**Anomalies to Look For:**
- USR-0004 (sarah.brown): Stale account (45 days inactive) but still has HR_Admin privileges
- USR-0017 (andrew.clark): Contractor with 147 days inactive - should be revoked
- USR-0009 (james.martinez): Inactive user (59 days)

### 2. `identity_events.csv` (300+ access events)
**Comprehensive access logs** showing user activities across systems with 35% anomaly density.

**Columns:**
- `timestamp` - When the activity happened
- `user_id` - Who did it
- `username` - Name
- `action` - What they did (login, sql_query, admin_operation, etc.)
- `resource` - What they accessed
- `resource_sensitivity` - Classification (low, medium, high)
- `status` - success or failure
- `source_ip` - Where they accessed from
- `time_classification` - business_hours, unusual_hours, night, week end
- `anomaly_marker` - Label indicating what's suspicious (for evaluation)

**Anomalies Embedded:**
- `STALE_ACCOUNT_LOGIN`: USR-0004 accessing HRIS despite being inactive 45 days
- `AFTER_HOURS_ADMIN_LOGIN`: USR-0005 (admin) logging in at 22:47
- `OFF_HOURS_DB_ACCESS`: USR-0008 accessing sensitive Customer_PII at 00:22
- `PRIVILEGE_CHANGE_OFF_HOURS`: Admin modifying IAM policies at night
- `CROSS_DEPARTMENT_ACCESS`: USR-0003 (Finance Analyst) accessing GL_System (unusual)

## How to Use These Datasets

### Load in Python:
```python
import pandas as pd

# Load users
users = pd.read_csv('identity_users.csv')
print(f"Total users: {len(users)}")
print(f"Active users: {users[users['is_active']==True].shape[0]}")

# Load events
events = pd.read_csv('identity_events.csv')
print(f"Total events: {len(events)}")
print(f"Date range: {events['timestamp'].min()} to {events['timestamp'].max()}")

# Merge for enriched view
events['user_detail'] = events['user_id'].map(users.set_index('user_id')['department'])
```

### Analysis Ideas:
1. **Stale Account Detection**: Who hasn't logged in for 30+ days but still has privileges?
2. **After-Hours Activity**: Who's accessing high-risk systems outside 9-5?
3. **Cross-Dept Access**: Who accesses systems outside their department?
4. **Privilege vs Activity**: Do admin accounts match their roles?
5. **Anomaly Scoring**: Combine multiple signals into a risk score

## Data Characteristics

- **Records**: 20 users, 50 events (sample size for demo)
- **Time Range**: April 15-17, 2026 (3 days)
- **Anomaly Ratio**: ~20% of events contain marked anomalies
- **Systems**: 10+ different systems (ERP, SIEM, Databases, cloud platforms)
- **Privileges**: Mix of user, power-user, and admin accounts

## Real-World Scale

For production:
- Expected Users: 2,000-10,000
- Expected Events: 500,000+ over 90 days
- This sample is 1% of realistic data volume

## Ground Truth

Anomalies are marked in `anomaly_marker` column. Use these to:
1. Validate your detection models
2. Calculate precision/recall metrics
3. Understand what constitutes "suspicious"

## Next Steps

1. **Explore the data** - Understand distributions, patterns
2. **Identify more anomalies** - Beyond the marked ones
3. **Build detection model** - Test anomaly detection algorithms
4. **Create dashboard** - Visualize findings
5. **Document approach** - Explain your methodology

---

**Questions?** See [PARTICIPANT_GUIDE.md](../../PARTICIPANT_GUIDE.md)
