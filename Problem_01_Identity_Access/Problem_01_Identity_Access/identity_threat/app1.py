"""
app.py  —  Identity Threat Intelligence SOC Dashboard
Dark SOC Theme | Flask + Plotly | Grok-powered explanations
"""
import os, json, math
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, abort
import pandas as pd
import plotly
import plotly.graph_objects as go

app = Flask(__name__)

# ── Paths ────────────────────────────────────────────────────────────────────
BASE = os.path.join(os.path.dirname(__file__), "..", "sample_data")

def _csv(name, fallback=None):
    p = os.path.join(BASE, name)
    if os.path.exists(p):
        return pd.read_csv(p)
    return fallback if fallback is not None else pd.DataFrame()

def load_data():
    users  = _csv("flagged_users.csv")
    events = _csv("flagged_events.csv")
    all_u  = _csv("identity_users_labels.csv")
    all_e  = _csv("identity_events_labels.csv")
    expl   = {}
    ep = os.path.join(BASE, "explanations.json")
    if os.path.exists(ep):
        with open(ep) as f:
            d = json.load(f)
        for u in d.get("user_explanations", []):
            expl[u.get("user_id")] = u
    return users, events, all_u, all_e, expl

# ── Design tokens ─────────────────────────────────────────────────────────────
COLORS = dict(
    bg="#0a0e1a", surface="#111827", border="#1f2937",
    crit="#ef4444", high="#f59e0b", med="#eab308", safe="#22c55e",
    text="#f9fafb", muted="#6b7280", accent="#3b82f6"
)

def sev_color(s):
    return {"CRITICAL": COLORS["crit"], "HIGH": COLORS["high"],
            "MEDIUM": COLORS["med"], "LOW": COLORS["safe"]}.get(str(s).upper(), COLORS["muted"])

def risk_badge(score):
    score = float(score) if score else 0
    if score >= 80: cl = "badge-crit"
    elif score >= 60: cl = "badge-high"
    elif score >= 40: cl = "badge-med"
    else: cl = "badge-safe"
    return f'<span class="{cl}">{score:.0f}</span>'

# ── Shared CSS + JS ───────────────────────────────────────────────────────────
HEAD = """
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}IDENTITY THREAT INTELLIGENCE{% endblock %}</title>
<meta name="description" content="SOC Identity Sprawl & Privilege Abuse Detection Dashboard">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--surface:#111827;--border:#1f2937;
  --crit:#ef4444;--high:#f59e0b;--med:#eab308;--safe:#22c55e;
  --text:#f9fafb;--muted:#6b7280;--accent:#3b82f6;
}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.mono{font-family:'JetBrains Mono',monospace}
/* Nav */
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 2rem;display:flex;align-items:center;gap:2rem;height:56px;position:sticky;top:0;z-index:100}
nav .brand{font-family:'JetBrains Mono',monospace;font-size:.85rem;font-weight:600;color:var(--crit);letter-spacing:.1em}
nav a{color:var(--muted);font-size:.85rem;font-weight:500;transition:color .2s}
nav a:hover,nav a.active{color:var(--text);text-decoration:none}
/* Layout */
.container{max-width:1400px;margin:0 auto;padding:2rem}
.page-header{margin-bottom:2rem}
.page-header h1{font-size:1.5rem;font-weight:700;letter-spacing:.05em}
.page-header p{color:var(--muted);margin-top:.25rem;font-size:.875rem}
/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem}
.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
@media(max-width:900px){.metric-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:500px){.metric-grid{grid-template-columns:1fr}}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem;text-align:center}
.metric-card .val{font-size:2.5rem;font-weight:700;font-family:'JetBrains Mono',monospace}
.metric-card .lbl{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:.25rem}
/* Badges */
.badge-crit{background:rgba(239,68,68,.15);color:var(--crit);border:1px solid rgba(239,68,68,.3);padding:.2rem .6rem;border-radius:.375rem;font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600}
.badge-high{background:rgba(245,158,11,.15);color:var(--high);border:1px solid rgba(245,158,11,.3);padding:.2rem .6rem;border-radius:.375rem;font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600}
.badge-med{background:rgba(234,179,8,.15);color:var(--med);border:1px solid rgba(234,179,8,.3);padding:.2rem .6rem;border-radius:.375rem;font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600}
.badge-safe{background:rgba(34,197,94,.15);color:var(--safe);border:1px solid rgba(34,197,94,.3);padding:.2rem .6rem;border-radius:.375rem;font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600}
.sev-crit{color:var(--crit)} .sev-high{color:var(--high)} .sev-med{color:var(--med)} .sev-safe{color:var(--safe)}
/* Table */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#0d1422;color:var(--muted);text-transform:uppercase;font-size:.7rem;letter-spacing:.08em;padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border)}
td{padding:.7rem 1rem;border-bottom:1px solid rgba(31,41,55,.6);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
tr.row-crit td{border-left:3px solid var(--crit)}
tr.row-high td{border-left:3px solid var(--high)}
tr.row-med  td{border-left:3px solid var(--med)}
tr.row-safe td{border-left:3px solid var(--safe)}
/* Alert feed */
.alert-item{display:flex;align-items:center;gap:.75rem;padding:.6rem 0;border-bottom:1px solid var(--border)}
.alert-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
/* Charts */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
@media(max-width:800px){.chart-grid{grid-template-columns:1fr}}
/* Filters */
.filter-bar{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.25rem}
.filter-bar select,.filter-bar input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.4rem .75rem;border-radius:.375rem;font-size:.85rem}
/* Blast radius */
.blast-box{border:1px solid var(--crit);border-radius:.75rem;padding:1.25rem;background:rgba(239,68,68,.05);margin-bottom:1.5rem}
.blast-box h3{color:var(--crit);font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:1rem}
.blast-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:600px){.blast-grid{grid-template-columns:1fr}}
.big-num{font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;color:var(--crit)}
/* Findings */
.finding-card{border:1px solid var(--border);border-radius:.5rem;padding:1rem;margin-bottom:.75rem}
.finding-card.sev-HIGH{border-left:3px solid var(--high)}
.finding-card.sev-CRITICAL{border-left:3px solid var(--crit)}
.finding-card.sev-MEDIUM{border-left:3px solid var(--med)}
/* Pulse indicator */
.pulse-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--crit);animation:pulse 1.5s infinite;margin-right:.5rem;vertical-align:middle}
/* Checklist */
.checklist{list-style:none;counter-reset:steps}
.checklist li{counter-increment:steps;padding:.5rem 0;display:flex;gap:.75rem;align-items:flex-start;color:var(--text);font-size:.875rem}
.checklist li::before{content:counter(steps);background:var(--accent);color:white;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;flex-shrink:0;margin-top:.1rem}
/* Compliance badges */
.comp-badge{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:var(--accent);padding:.25rem .6rem;border-radius:.375rem;font-size:.75rem;font-weight:600;display:inline-block;margin:.2rem}
/* Simulate */
.sim-node{background:var(--surface);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1.25rem;margin:.4rem 0;display:flex;align-items:center;gap:.75rem;font-family:'JetBrains Mono',monospace;font-size:.85rem;animation:slideIn .5s ease}
@keyframes slideIn{from{opacity:0;transform:translateX(-20px)}to{opacity:1;transform:translateX(0)}}
.chain-arrow{color:var(--crit);text-align:center;font-size:1.2rem;margin:.2rem 0}
</style>
</head>
"""

NAV = """
<nav>
  <span class="brand">◉ IDENTITY THREAT INTEL</span>
  <a href="/" class="{{ 'active' if active=='home' else '' }}">Command Center</a>
  <a href="/users" class="{{ 'active' if active=='users' else '' }}">Users</a>
  <a href="/events" class="{{ 'active' if active=='events' else '' }}">Events</a>
</nav>
"""

BASE_TMPL = """<!DOCTYPE html>
<html lang="en">
""" + HEAD + """
<body>
""" + NAV + """
<div class="container">
{% block content %}{% endblock %}
</div>
</body></html>
"""

# ── Plotly dark config ────────────────────────────────────────────────────────
DARK = dict(paper_bgcolor="#0a0e1a", plot_bgcolor="#111827",
            font=dict(color="#f9fafb", family="Inter"),
            xaxis=dict(gridcolor="#1f2937", showgrid=True),
            yaxis=dict(gridcolor="#1f2937", showgrid=True),
            margin=dict(l=40, r=20, t=40, b=40))

def fig_json(fig):
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/live-feed")
def live_feed():
    _, events, _, _, _ = load_data()
    if events.empty:
        return jsonify([])
    cols = ["timestamp","user_id","username","action","resource",
            "resource_sensitivity","risk_score","severity"]
    cols = [c for c in cols if c in events.columns]
    last10 = events.sort_values("risk_score", ascending=False).head(10)[cols]
    return jsonify(last10.fillna("").to_dict("records"))


def _page(body, title="IDENTITY THREAT INTELLIGENCE", active="home"):
    _nav = (f'<nav><span class="brand">◉ IDENTITY THREAT INTEL</span>'
            f'<a href="/" {"class=\"active\"" if active=="home" else ""}>Command Center</a>'
            f'<a href="/users" {"class=\"active\"" if active=="users" else ""}>Users</a>'
            f'<a href="/events" {"class=\"active\"" if active=="events" else ""}>Events</a>'
            f'</nav>')
    _head = HEAD.replace("{% block title %}IDENTITY THREAT INTELLIGENCE{% endblock %}", title)
    return f"<!DOCTYPE html><html lang='en'>{_head}<body>{_nav}<div class='container'>{body}</div></body></html>"


@app.route("/")
def index():
    users, events, all_u, all_e, expl = load_data()

    has_crit = (not users.empty and
                "severity" in users.columns and
                (users["severity"] == "CRITICAL").any())

    total_u   = len(all_u) if not all_u.empty else len(users)
    anom_u    = len(users)
    crit_cnt  = int((users["severity"]=="CRITICAL").sum()) if not users.empty and "severity" in users.columns else 0
    sys_at_risk = int(users["num_systems"].sum()) if not users.empty and "num_systems" in users.columns else 0

    # ── Dept risk bar chart
    dept_fig = go.Figure()
    if not users.empty and "department" in users.columns and "risk_score" in users.columns:
        dept_avg = users.groupby("department")["risk_score"].mean().sort_values(ascending=False).head(10)
        dept_fig.add_trace(go.Bar(
            x=dept_avg.index.tolist(), y=dept_avg.values.tolist(),
            marker_color=[COLORS["crit"] if v>=80 else COLORS["high"] if v>=60
                          else COLORS["med"] for v in dept_avg.values],
            name="Avg Risk Score"
        ))
    dept_fig.update_layout(**DARK, title="Avg Risk Score by Department", height=300)
    dept_json = fig_json(dept_fig)

    # ── Events over time line chart
    evt_fig = go.Figure()
    if not events.empty and "timestamp" in events.columns:
        events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
        cutoff = datetime.now() - timedelta(days=30)
        recent = events[events["timestamp"] >= cutoff].copy()
        if not recent.empty:
            recent["date"] = recent["timestamp"].dt.date
            daily = recent.groupby("date").size().reset_index(name="count")
            evt_fig.add_trace(go.Scatter(
                x=daily["date"].astype(str).tolist(),
                y=daily["count"].tolist(),
                mode="lines+markers",
                line=dict(color=COLORS["accent"], width=2),
                fill="tozeroy", fillcolor="rgba(59,130,246,0.1)",
                name="Anomalous Events"
            ))
    evt_fig.update_layout(**DARK, title="Anomalous Events (Last 30 Days)", height=300)
    evt_json = fig_json(evt_fig)

    # ── Top 5 critical user cards
    top5 = users.head(5).to_dict("records") if not users.empty else []

    # ── Last 10 critical events for feed
    feed = []
    if not events.empty:
        cols = ["timestamp","username","action","resource","risk_score","severity"]
        cols = [c for c in cols if c in events.columns]
        feed = events.sort_values("risk_score", ascending=False).head(10)[cols].fillna("").to_dict("records")

    pulse = '<span class="pulse-dot"></span>' if has_crit else ''

    SBC = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}
    def _bc(sv): return SBC.get(str(sv).upper(), "safe")
    def _bd(sv): return SBC.get(str(sv).upper(), "muted")

    feed_html = ""
    for ev in feed:
        bc_ev = _bc(ev.get("severity", ""))
        feed_html += (
            f'<div class="alert-item">'
            f'<div class="alert-dot" style="background:var(--{_bd(ev.get("severity",""))})"></div>'
            f'<div style="flex:1;min-width:0">'
            f'<div style="font-size:.8rem;font-family:\'JetBrains Mono\',monospace">{ev.get("username","")} &rarr; {ev.get("resource","")}</div>'
            f'<div style="font-size:.7rem;color:var(--muted)">{ev.get("action","")} | {str(ev.get("timestamp",""))[:16]}</div>'
            f'</div><span class="badge-{bc_ev}">{int(float(ev.get("risk_score",0)))}</span></div>'
        )

    top5_html = ""
    for u in top5:
        bc_u  = _bc(u.get("severity", ""))
        col_u = "crit" if str(u.get("severity","")).upper()=="CRITICAL" else "high"
        top5_html += (
            f'<a href="/user/{u.get("user_id","")}" style="display:block;text-decoration:none">'
            f'<div class="card" style="margin-bottom:.5rem;padding:.875rem;border-left:3px solid var(--{col_u});cursor:pointer;transition:background .2s"'
            f' onmouseover="this.style.background=\'rgba(255,255,255,0.03)\'" onmouseout="this.style.background=\'\'">'
            f'<div style="display:flex;justify-content:space-between;align-items:center">'
            f'<div><div style="font-family:\'JetBrains Mono\',monospace;font-size:.85rem;color:var(--text)">{u.get("user_id","")} &mdash; {u.get("username","")}</div>'
            f'<div style="font-size:.75rem;color:var(--muted)">{u.get("department","")} | {u.get("privilege_level","")} | {int(float(u.get("days_inactive",0)))}d inactive</div></div>'
            f'<span class="badge-{bc_u}">{int(float(u.get("risk_score",0)))}</span>'
            f'</div></div></a>'
        )

    body = f"""
<div class="page-header" style="display:flex;align-items:center;gap:1rem">
  {pulse}
  <div><h1>IDENTITY THREAT INTELLIGENCE</h1>
  <p>Real-time privilege abuse &amp; identity sprawl detection</p></div>
</div>
<div class="metric-grid">
  <div class="metric-card"><div class="val" style="color:var(--accent)">{total_u}</div><div class="lbl">Total Users</div></div>
  <div class="metric-card"><div class="val" style="color:var(--high)">{anom_u}</div><div class="lbl">Anomalous</div></div>
  <div class="metric-card"><div class="val" style="color:var(--crit)">{crit_cnt}</div><div class="lbl">Critical Alerts</div></div>
  <div class="metric-card"><div class="val" style="color:var(--med)">{sys_at_risk}</div><div class="lbl">Systems at Risk</div></div>
</div>
<div class="chart-grid">
  <div class="card"><div id="deptChart"></div></div>
  <div class="card"><div id="evtChart"></div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem">
  <div class="card">
    <h2 style="font-size:.85rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:1rem">&#9889; Live Alert Feed <span style="font-size:.7rem">(auto-refresh 10s)</span></h2>
    <div id="alertFeed">{feed_html}</div>
  </div>
  <div class="card">
    <h2 style="font-size:.85rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:1rem">&#128680; Top 5 Critical Users</h2>
    {top5_html}
  </div>
</div>
<script>
var dj={dept_json};var ej={evt_json};
Plotly.newPlot('deptChart',dj.data,dj.layout,{{responsive:true,displayModeBar:false}});
Plotly.newPlot('evtChart',ej.data,ej.layout,{{responsive:true,displayModeBar:false}});
async function refreshFeed(){{
  try{{
    const r=await fetch('/api/live-feed');const d=await r.json();
    const s={{CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'safe'}};
    document.getElementById('alertFeed').innerHTML=d.map(e=>`<div class="alert-item"><div class="alert-dot" style="background:var(--${{s[e.severity]||'muted'}})"></div><div style="flex:1;min-width:0"><div style="font-size:.8rem;font-family:'JetBrains Mono',monospace">${{e.username||''}} &rarr; ${{e.resource||''}}</div><div style="font-size:.7rem;color:var(--muted)">${{e.action||''}} | ${{(e.timestamp||'').slice(0,16)}}</div></div><span class="badge-${{s[e.severity]||'safe'}}">${{Math.round(e.risk_score||0)}}</span></div>`).join('');
  }}catch(err){{}}
}}
setInterval(refreshFeed,10000);
</script>"""
    return _page(body, "Command Center — Identity Threat Intel", "home")


# ── /users ────────────────────────────────────────────────────────────────────
@app.route("/users")
def users_page():
    users, _, _, _, _ = load_data()
    sev_f  = request_arg("sev", "")
    dept_f = request_arg("dept", "")
    priv_f = request_arg("priv", "")

    df = users.copy() if not users.empty else pd.DataFrame()
    if not df.empty:
        if sev_f:  df = df[df.get("severity","").str.upper() == sev_f.upper()] if "severity" in df.columns else df
        if dept_f: df = df[df["department"].str.lower().str.contains(dept_f.lower(), na=False)] if "department" in df.columns else df
        if priv_f: df = df[df["privilege_level"].str.lower() == priv_f.lower()] if "privilege_level" in df.columns else df

    severities = sorted(users["severity"].dropna().unique().tolist()) if not users.empty and "severity" in users.columns else []
    depts      = sorted(users["department"].dropna().unique().tolist()) if not users.empty and "department" in users.columns else []
    privs      = sorted(users["privilege_level"].dropna().unique().tolist()) if not users.empty and "privilege_level" in users.columns else []

    rows_html = ""
    if not df.empty:
        for _, r in df.iterrows():
            sc = str(r.get("severity","LOW")).upper()
            rc = {"CRITICAL":"row-crit","HIGH":"row-high","MEDIUM":"row-med"}.get(sc,"row-safe")
            bc = {"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med"}.get(sc,"badge-safe")
            rows_html += (
                f'<tr class="{rc}" onclick="location.href=\'/user/{r.get("user_id","")}\'" style="cursor:pointer">'
                f'<td><span class="mono" style="color:var(--accent)">{r.get("user_id","")}</span><br>'
                f'<span style="font-size:.8rem;color:var(--muted)">{r.get("username","")}</span></td>'
                f'<td>{r.get("department","")}</td>'
                f'<td><span class="mono" style="font-size:.8rem">{r.get("privilege_level","")}</span></td>'
                f'<td class="mono">{int(r.get("days_inactive",0))}</td>'
                f'<td>{int(r.get("num_systems",0))}</td>'
                f'<td><span class="{bc}">{float(r.get("risk_score",0)):.0f}</span></td>'
                f'<td style="color:{sev_color(sc)};font-weight:600;font-size:.8rem">{sc}</td>'
                f'<td><a href="/user/{r.get("user_id","")}" style="font-size:.8rem">Details →</a> '
                f'<a href="/simulate/{r.get("user_id","")}" style="font-size:.8rem;color:var(--crit)">Simulate</a></td>'
                f'</tr>'
            )

    sev_opts = "".join(f'<option value="{s}" {"selected" if s==sev_f else ""}>{s}</option>' for s in severities)
    dept_opts = "".join(f'<option value="{d}" {"selected" if d==dept_f else ""}>{d}</option>' for d in depts)
    priv_opts = "".join(f'<option value="{p}" {"selected" if p==priv_f else ""}>{p}</option>' for p in privs)

    body = f"""
<div class="page-header"><h1>USER RISK TABLE</h1><p>{len(df)} flagged accounts</p></div>
<form method="get" class="filter-bar">
  <select name="sev"><option value="">All Severities</option>{sev_opts}</select>
  <select name="dept"><option value="">All Departments</option>{dept_opts}</select>
  <select name="priv"><option value="">All Privileges</option>{priv_opts}</select>
  <button type="submit" style="background:var(--accent);color:white;border:none;padding:.4rem 1rem;border-radius:.375rem;cursor:pointer;font-size:.85rem">Filter</button>
  <a href="/users" style="padding:.4rem 1rem;font-size:.85rem;color:var(--muted)">Reset</a>
</form>
<div class="card tbl-wrap">
<table id="usersTable">
<thead><tr>
  <th>User</th><th>Department</th><th>Privilege</th>
  <th>Inactive Days</th><th>Systems</th><th>Risk Score</th>
  <th>Severity</th><th>Actions</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>"""
    return _page(body, "Users — Identity Threat Intel", "users")


def request_arg(name, default=""):
    from flask import request
    return request.args.get(name, default)


# ── /events ───────────────────────────────────────────────────────────────────
@app.route("/events")
def events_page():
    _, events, _, _, _ = load_data()
    sev_f    = request_arg("sev", "")
    action_f = request_arg("action", "")
    sens_f   = request_arg("sens", "")

    df = events.copy() if not events.empty else pd.DataFrame()
    if not df.empty:
        if sev_f    and "severity"            in df.columns: df = df[df["severity"].str.upper()==sev_f.upper()]
        if action_f and "action"              in df.columns: df = df[df["action"]==action_f]
        if sens_f   and "resource_sensitivity" in df.columns: df = df[df["resource_sensitivity"]==sens_f]

    actions = sorted(events["action"].dropna().unique().tolist()) if not events.empty and "action" in events.columns else []
    sevs    = sorted(events["severity"].dropna().unique().tolist()) if not events.empty and "severity" in events.columns else []
    senss   = sorted(events["resource_sensitivity"].dropna().unique().tolist()) if not events.empty and "resource_sensitivity" in events.columns else []

    rows_html = ""
    if not df.empty:
        for _, r in df.head(200).iterrows():
            sc = str(r.get("severity","LOW")).upper()
            rc = {"CRITICAL":"row-crit","HIGH":"row-high","MEDIUM":"row-med"}.get(sc,"row-safe")
            bc = {"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med"}.get(sc,"badge-safe")
            ts = str(r.get("timestamp",""))[:16]
            rows_html += (
                f'<tr class="{rc}">'
                f'<td class="mono" style="font-size:.75rem">{ts}</td>'
                f'<td><a href="/user/{r.get("user_id","")}" class="mono" style="font-size:.8rem">{r.get("username","")}</a></td>'
                f'<td style="font-size:.8rem">{r.get("action","")}</td>'
                f'<td style="font-size:.8rem">{r.get("resource","")}</td>'
                f'<td><span style="font-size:.75rem;color:{sev_color(r.get("resource_sensitivity","low").upper())}">{r.get("resource_sensitivity","")}</span></td>'
                f'<td class="mono" style="font-size:.8rem">{int(r.get("rowcount",0)):,}</td>'
                f'<td style="font-size:.75rem;color:var(--muted)">{r.get("destination","local")}</td>'
                f'<td><span class="{bc}">{float(r.get("risk_score",0)):.0f}</span></td>'
                f'</tr>'
            )

    sev_opts    = "".join(f'<option value="{s}" {"selected" if s==sev_f else ""}>{s}</option>' for s in sevs)
    action_opts = "".join(f'<option value="{a}" {"selected" if a==action_f else ""}>{a}</option>' for a in actions)
    sens_opts   = "".join(f'<option value="{s}" {"selected" if s==sens_f else ""}>{s}</option>' for s in senss)

    body = f"""
<div class="page-header"><h1>EVENT LOG</h1><p>Showing up to 200 of {len(df)} flagged events</p></div>
<form method="get" class="filter-bar">
  <select name="sev"><option value="">All Severities</option>{sev_opts}</select>
  <select name="action"><option value="">All Actions</option>{action_opts}</select>
  <select name="sens"><option value="">All Sensitivity</option>{sens_opts}</select>
  <button type="submit" style="background:var(--accent);color:white;border:none;padding:.4rem 1rem;border-radius:.375rem;cursor:pointer;font-size:.85rem">Filter</button>
  <a href="/events" style="padding:.4rem 1rem;font-size:.85rem;color:var(--muted)">Reset</a>
</form>
<div class="card tbl-wrap">
<table>
<thead><tr>
  <th>Time</th><th>User</th><th>Action</th><th>Resource</th>
  <th>Sensitivity</th><th>Records</th><th>Destination</th><th>Risk Score</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>"""
    return _page(body, "Events — Identity Threat Intel", "events")


# ── /user/<id> ────────────────────────────────────────────────────────────────
@app.route("/user/<user_id>")
def user_detail(user_id):
    users, events, _, _, expl = load_data()
    row = None
    if not users.empty and "user_id" in users.columns:
        m = users[users["user_id"] == user_id]
        if not m.empty:
            row = m.iloc[0]
    if row is None:
        return _page(f"<div class='card'><h2>User {user_id} not found</h2></div>", active="users")

    sc = str(row.get("severity","LOW")).upper()
    bc = {"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med"}.get(sc,"badge-safe")

    # Timeline chart
    tl_fig = go.Figure()
    if not events.empty and "user_id" in events.columns:
        uev = events[events["user_id"]==user_id].copy()
        uev["timestamp"] = pd.to_datetime(uev["timestamp"], errors="coerce")
        uev = uev.sort_values("timestamp")
        if not uev.empty:
            tl_fig.add_trace(go.Scatter(
                x=uev["timestamp"].astype(str).tolist(),
                y=uev["risk_score"].tolist() if "risk_score" in uev.columns else [0]*len(uev),
                mode="markers+lines",
                marker=dict(color=[sev_color(s) for s in uev.get("severity", pd.Series(["LOW"]*len(uev)))], size=8),
                line=dict(color="#3b82f6"),
                text=uev.get("action",""),
                name="Events"
            ))
    tl_fig.update_layout(**DARK, title="Event Timeline", height=250)
    tl_json = fig_json(tl_fig)

    exp = expl.get(user_id, {})

    # Blast radius
    br = exp.get("blast_radius", {})
    systems_list = row.get("systems_access","").split("|") if row.get("systems_access") else []
    br_systems   = br.get("systems_at_risk", systems_list)
    br_records   = br.get("estimated_records_exposed", 0)
    br_gdpr      = br.get("gdpr_fine_exposure", "€20M or 4% global revenue")
    br_impact    = br.get("business_impact", "Potential data exfiltration risk.")

    sys_pills = "".join(f'<span style="display:inline-block;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:var(--crit);padding:.2rem .6rem;border-radius:.375rem;font-size:.75rem;margin:.2rem;font-family:\'JetBrains Mono\',monospace">{s}</span>' for s in (br_systems if isinstance(br_systems,list) else str(br_systems).split("|")))

    findings_html = ""
    for fn in exp.get("findings", []):
        fc = fn.get("severity","MEDIUM")
        findings_html += f"""<div class="finding-card sev-{fc}">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem">
    <span class="mono" style="font-size:.8rem;font-weight:600">{fn.get("finding","FINDING")}</span>
    <span class="badge-{'crit' if fc=='CRITICAL' else 'high' if fc=='HIGH' else 'med'}">{fc}</span>
  </div>
  <p style="font-size:.85rem;color:var(--text);margin-bottom:.5rem">{fn.get("details","")}</p>
  <p style="font-size:.8rem;color:var(--accent)">→ {fn.get("recommendation","")}</p>
</div>"""

    if not findings_html:
        findings_html = '<div class="card" style="color:var(--muted);font-size:.875rem">Analysis pending — run explainer.py to generate LLM explanations.</div>'

    comp_html = "".join(f'<span class="comp-badge">{c}</span>' for c in exp.get("compliance_violations",[]))
    actions_html = "".join(f"<li>{a}</li>" for a in exp.get("suggested_actions",[]))

    body = f"""
<div class="page-header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem">
    <div>
      <p style="color:var(--muted);font-size:.75rem;letter-spacing:.1em;text-transform:uppercase">Subject Profile</p>
      <h1 class="mono">{user_id} — {row.get("username","")}</h1>
      <p>{row.get("department","")} | {row.get("job_title","")}</p>
    </div>
    <span class="{bc}" style="font-size:1.5rem;padding:.5rem 1.5rem">{float(row.get("risk_score",0)):.0f}</span>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem">
  <div class="card">
    <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem">Account Details</h3>
    <table style="width:100%">
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Privilege</td><td class="mono" style="font-size:.8rem">{row.get("privilege_level","")}</td></tr>
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Status</td><td style="font-size:.8rem;color:{'var(--safe)' if row.get('is_active') else 'var(--crit)'}">{row.get("is_active","")}</td></tr>
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Days Inactive</td><td class="mono" style="font-size:.8rem;color:var(--high)">{int(row.get("days_inactive",0))}</td></tr>
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Hire Date</td><td class="mono" style="font-size:.8rem">{row.get("hire_date","")}</td></tr>
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Systems</td><td class="mono" style="font-size:.8rem">{int(row.get("num_systems",0))}</td></tr>
      <tr><td style="color:var(--muted);font-size:.8rem;padding:.3rem 0">Severity</td><td style="color:{sev_color(sc)};font-weight:600;font-size:.8rem">{sc}</td></tr>
    </table>
  </div>
  <div class="card"><div id="timeline"></div></div>
</div>

<div class="blast-box">
  <h3>💥 BLAST RADIUS — <a href="/simulate/{user_id}" style="color:var(--crit);font-size:.85rem">Run Simulation →</a></h3>
  <div class="blast-grid">
    <div>
      <p style="color:var(--muted);font-size:.7rem;text-transform:uppercase;margin-bottom:.5rem">Systems at Risk</p>
      {sys_pills}
    </div>
    <div>
      <p style="color:var(--muted);font-size:.7rem;text-transform:uppercase;margin-bottom:.25rem">Records Exposed</p>
      <div class="big-num">{int(br_records):,}</div>
    </div>
    <div>
      <p style="color:var(--muted);font-size:.7rem;text-transform:uppercase;margin-bottom:.25rem">GDPR Fine Exposure</p>
      <div class="big-num" style="font-size:1.2rem">{br_gdpr}</div>
    </div>
    <div>
      <p style="color:var(--muted);font-size:.7rem;text-transform:uppercase;margin-bottom:.25rem">Business Impact</p>
      <p style="font-size:.85rem;color:var(--text)">{br_impact}</p>
    </div>
  </div>
</div>

<div class="card" style="margin-bottom:1.5rem">
  <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem">🔍 LLM Findings</h3>
  {findings_html}
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
  <div class="card">
    <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem">Compliance Violations</h3>
    {comp_html if comp_html else '<span style="color:var(--muted);font-size:.875rem">None detected</span>'}
  </div>
  <div class="card">
    <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem">Recommended Actions</h3>
    <ol class="checklist">{actions_html}</ol>
    {'<p style="font-size:.8rem;color:var(--crit);margin-top:.75rem">⏰ '+exp.get("next_escalation","")+'</p>' if exp.get("next_escalation") else ""}
  </div>
</div>

<script>
var tl = {tl_json};
Plotly.newPlot('timeline', tl.data, tl.layout, {{responsive:true, displayModeBar:false}});
</script>"""
    return _page(body, f"{user_id} — Identity Threat Intel", "users")


# ── /simulate/<id> ────────────────────────────────────────────────────────────
@app.route("/simulate/<user_id>")
def simulate(user_id):
    users, _, _, _, expl = load_data()
    row = None
    if not users.empty and "user_id" in users.columns:
        m = users[users["user_id"]==user_id]
        if not m.empty: row = m.iloc[0]
    if row is None:
        return _page(f"<p>User {user_id} not found</p>", active="users")

    systems = str(row.get("systems_access","")).split("|")
    exp = expl.get(user_id, {})
    br  = exp.get("blast_radius", {})
    records = br.get("estimated_records_exposed", len(systems)*250000)
    gdpr    = br.get("gdpr_fine_exposure", "€20M or 4% global revenue")
    impact  = br.get("business_impact", "Unauthorized data access across multiple systems.")

    sys_nodes = "".join(
        f'<div class="sim-node" style="animation-delay:{i*0.15}s">'
        f'<span style="color:var(--crit)">⚠</span>'
        f'<div><div style="font-weight:600">{s}</div>'
        f'<div style="font-size:.7rem;color:var(--muted)">Full access compromised</div></div>'
        f'</div><div class="chain-arrow">↓</div>'
        for i, s in enumerate(systems)
    )

    body = f"""
<div style="max-width:700px;margin:0 auto">
  <div class="page-header" style="text-align:center">
    <p style="color:var(--crit);font-size:.75rem;letter-spacing:.15em;text-transform:uppercase;margin-bottom:.5rem">⚠ BREACH SIMULATION</p>
    <h1 style="font-size:1.75rem">IF {row.get("username","this account").upper()} IS COMPROMISED...</h1>
    <p style="color:var(--muted)">Attacker kill chain analysis for {user_id}</p>
  </div>

  <div class="blast-box" style="margin-bottom:2rem">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;text-align:center">
      <div><div class="big-num">{len(systems)}</div><p style="font-size:.7rem;color:var(--muted);text-transform:uppercase">Systems Compromised</p></div>
      <div><div class="big-num" style="font-size:1.5rem">{int(records):,}</div><p style="font-size:.7rem;color:var(--muted);text-transform:uppercase">Records at Risk</p></div>
      <div><div class="big-num" style="font-size:1.1rem">{gdpr}</div><p style="font-size:.7rem;color:var(--muted);text-transform:uppercase">GDPR Exposure</p></div>
    </div>
  </div>

  <div class="card" style="margin-bottom:1.5rem">
    <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem">Attack Cascade</h3>
    <div class="sim-node" style="border-color:var(--crit);background:rgba(239,68,68,.05)">
      <span style="color:var(--crit)">🔓</span>
      <div><div style="font-weight:700;color:var(--crit)">INITIAL ACCESS — {user_id}</div>
      <div style="font-size:.7rem;color:var(--muted)">{row.get("privilege_level","")} account | {int(row.get("days_inactive",0))}d inactive</div>
      </div>
    </div>
    <div class="chain-arrow">↓</div>
    {sys_nodes}
    <div class="sim-node" style="border-color:var(--crit);background:rgba(239,68,68,.08)">
      <span>☠</span>
      <div><div style="font-weight:700;color:var(--crit)">EXFILTRATION COMPLETE</div>
      <div style="font-size:.7rem;color:var(--muted)">{int(records):,} records extracted</div></div>
    </div>
  </div>

  <div class="card" style="margin-bottom:1.5rem">
    <h3 style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem">Business Impact</h3>
    <p style="font-size:.9rem">{impact}</p>
    {'<div style="margin-top:.75rem;padding:.75rem;background:rgba(239,68,68,.05);border-radius:.375rem;font-size:.85rem;color:var(--crit)">⚠ SIEM access detected — attacker can cover tracks and evade detection</div>' if "SIEM" in systems else ""}
  </div>

  <div style="text-align:center;margin-top:2rem">
    <a href="/user/{user_id}" style="background:var(--crit);color:white;padding:.75rem 2rem;border-radius:.5rem;font-weight:600;text-decoration:none;margin-right:1rem">View Full Profile</a>
    <a href="/users" style="background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.75rem 2rem;border-radius:.5rem;font-weight:600;text-decoration:none">Back to Users</a>
  </div>
</div>"""
    return _page(body, f"Simulate — {user_id}", "users")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
