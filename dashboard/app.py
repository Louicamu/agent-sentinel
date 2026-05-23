"""
AgentSentinel — Streamlit Dashboard
=====================================
Professional dark-themed Streamlit dashboard for the AgentSentinel
penetration testing framework. Designed for live hackathon demo.

Run:
  streamlit run dashboard/app.py

Requires: streamlit, plotly, requests (pip install streamlit plotly requests)
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Any

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure we can import from dashboard package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demo_sequence import (
    DEMO_SEQUENCE,
    ELASTIC_CORRELATION_STATS,
    FINDINGS,
    OWASP_MAPPINGS,
    SCAN_HISTORY,
)

# ---------------------------------------------------------------------------
# Page configuration — MUST be first Streamlit command
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AgentSentinel — AI Agent Security Scanner",
    page_icon="⚠",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark theme with professional styling
# ---------------------------------------------------------------------------

st.markdown(
    """
<style>
    /* Base dark theme overrides */
    .stApp {
        background-color: #0e1117;
        color: #e0e0e0;
    }
    .stMarkdown, .stText, p, li, h1, h2, h3, h4, h5, h6 {
        color: #e0e0e0 !important;
    }
    .stSidebar {
        background-color: #161a23;
        border-right: 1px solid #2a2f3a;
    }
    .stSidebar .stMarkdown, .stSidebar p, .stSidebar li {
        color: #b0b8c8 !important;
    }
    .stButton > button {
        background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
        color: white !important;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.5rem;
        font-weight: 600;
        letter-spacing: 0.3px;
        transition: all 0.2s;
        width: 100%;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(37, 99, 235, 0.4);
    }
    .stButton > button:disabled {
        background: #3a3f4b !important;
        color: #6b7280 !important;
        cursor: not-allowed;
        transform: none;
        box-shadow: none;
    }
    .stTextInput > div > div > input,
    .stSelectbox > div > div,
    .stSelectbox > div > div > div {
        background-color: #1e2330;
        border: 1px solid #2a2f3a;
        color: #e0e0e0;
        border-radius: 6px;
    }
    .stTextInput > div > div > input:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
    }
    .stCheckbox > label {
        color: #c0c8d8 !important;
    }
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #2563eb, #7c3aed);
    }
    .stTabs [data-baseweb="tab-list"] {
        background-color: #161a23;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        padding: 8px 20px;
        color: #9ca3af;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2563eb !important;
        color: white !important;
    }
    .stExpander {
        background-color: #1a1f2c;
        border: 1px solid #2a2f3a;
        border-radius: 8px;
        margin-bottom: 8px;
    }
    .stExpander > div > div > div > div {
        color: #e0e0e0 !important;
    }
    .stDataFrame {
        background-color: #161a23 !important;
    }
    .stDataFrame [data-testid="StyledDataFrame"] {
        background-color: #161a23 !important;
    }
    div[data-testid="stDataFrame"] div[data-testid="StyledDataFrame"] table {
        background-color: #161a23 !important;
    }

    /* Custom finding card styling */
    .finding-card {
        background: linear-gradient(135deg, #1a1f2c 0%, #1e2535 100%);
        border: 1px solid #2a2f3a;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        transition: all 0.2s;
    }
    .finding-card:hover {
        border-color: #4a5568;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
    }
    .severity-critical {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        color: white;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        display: inline-block;
    }
    .severity-high {
        background: linear-gradient(135deg, #ea580c 0%, #9a3412 100%);
        color: white;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        display: inline-block;
    }
    .severity-medium {
        background: linear-gradient(135deg, #ca8a04 0%, #854d0e 100%);
        color: white;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        display: inline-block;
    }
    .severity-low {
        background: linear-gradient(135deg, #2563eb 0%, #1e3a5f 100%);
        color: white;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        display: inline-block;
    }
    .severity-info {
        background: linear-gradient(135deg, #6b7280 0%, #374151 100%);
        color: white;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        display: inline-block;
    }
    .finding-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #f0f0f0 !important;
        margin: 8px 0 4px 0;
    }
    .finding-category {
        color: #9ca3af !important;
        font-size: 0.85rem;
    }
    .finding-evidence {
        background-color: #0d1117;
        border: 1px solid #2a2f3a;
        border-radius: 6px;
        padding: 12px;
        font-family: 'SF Mono', 'Consolas', 'Monaco', monospace;
        font-size: 0.8rem;
        color: #a0d8a0 !important;
        white-space: pre-wrap;
        margin-top: 8px;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2c 0%, #1e2535 100%);
        border: 1px solid #2a2f3a;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #f0f0f0 !important;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #9ca3af !important;
        margin-top: 4px;
    }
    .header-title {
        font-size: 1.6rem;
        font-weight: 700;
        background: linear-gradient(135deg, #2563eb, #7c3aed);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .header-subtitle {
        font-size: 0.9rem;
        color: #9ca3af !important;
        margin-top: -4px;
    }
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .systemic-card {
        background: linear-gradient(135deg, #1e1a2c 0%, #251e35 100%);
        border: 1px solid #5b3a8a;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 12px;
    }
    .systemic-card p {
        color: #c8b0e0 !important;
    }
    .stAlert {
        background-color: #1a1f2c !important;
        border: 1px solid #2a2f3a !important;
        color: #e0e0e0 !important;
    }
    footer { display: none; }
    #MainMenu { display: none; }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session state initialization
# ---------------------------------------------------------------------------

_DEFAULT_STATE: dict[str, Any] = {
    "scan_running": False,
    "scan_complete": False,
    "current_step": 0,
    "findings_found": [],
    "scan_progress": 0.0,
    "demo_mode": False,
    "target_url": "http://localhost:8765",
    "selected_categories": [
        "Prompt Injection",
        "Tool Misuse",
        "Broken Access Control",
        "Code Injection",
        "Context Manipulation",
    ],
    "active_tab": "Live Scan",
}

for key, default in _DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def severity_class(severity: str) -> str:
    """Return CSS class for severity badge."""
    mapping = {
        "Critical": "severity-critical",
        "High": "severity-high",
        "Medium": "severity-medium",
        "Low": "severity-low",
        "Info": "severity-info",
    }
    return mapping.get(severity, "severity-info")


def severity_color(severity: str) -> str:
    """Return hex color for severity."""
    mapping = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#2563eb",
        "Info": "#6b7280",
    }
    return mapping.get(severity, "#6b7280")


def finding_card_html(finding_key: str, finding: dict[str, Any]) -> str:
    """Generate HTML for a finding card."""
    sev = finding.get("severity", "Info")
    sev_class = severity_class(sev)
    return f"""
    <div class="finding-card">
        <div>
            <span class="{sev_class}">{sev}</span>
            <span style="color:#6b7280;font-size:0.8rem;margin-left:8px;">
                {finding.get("id", "")}
            </span>
        </div>
        <div class="finding-title">{finding.get("title", "Unknown Finding")}</div>
        <div class="finding-category">
            {finding.get("category", "")} &middot; {finding.get("owasp", "")}
        </div>
        <div style="margin-top:10px;color:#c0c8d8 !important;font-size:0.9rem;">
            {finding.get("description", "")}
        </div>
        <details style="margin-top:10px;">
            <summary style="color:#9ca3af;cursor:pointer;font-size:0.85rem;">
                Evidence & Reproduction
            </summary>
            <div class="finding-evidence">
                <strong>Evidence:</strong>
                {finding.get("evidence", "")}
                <br><br>
                <strong>Reproduction:</strong>
                {finding.get("reproduction", "")}
            </div>
        </details>
        <div style="margin-top:8px;font-size:0.75rem;color:#6b7280 !important;">
            {finding.get("affected_component", "")}
        </div>
    </div>
    """


def run_demo_scan():
    """Execute the demo scan sequence, updating state step by step."""
    st.session_state.scan_running = True
    st.session_state.scan_complete = False
    st.session_state.findings_found = []
    st.session_state.current_step = 0
    st.session_state.scan_progress = 0.0

    total_steps = len(DEMO_SEQUENCE)
    start_time = time.time()

    for i, step in enumerate(DEMO_SEQUENCE):
        if not st.session_state.scan_running:
            break

        st.session_state.current_step = i

        # Calculate progress (with some headroom for the "complete" step)
        progress = (i + 1) / total_steps
        st.session_state.scan_progress = min(progress, 0.98)

        # Sleep for the specified delay
        delay = step.get("delay", 1.0)
        # Adjust for actual elapsed time
        elapsed = time.time() - start_time
        remaining = delay - elapsed
        if remaining > 0:
            time.sleep(min(remaining, 2.0))

        if step["action"] == "show_finding":
            finding_key = step.get("finding", "")
            if finding_key and finding_key in FINDINGS:
                if finding_key not in st.session_state.findings_found:
                    st.session_state.findings_found.append(finding_key)

        # Re-run the app to show progress
        st.rerun()

    st.session_state.scan_running = False
    st.session_state.scan_complete = True
    st.session_state.scan_progress = 1.0
    st.rerun()


def render_live_scan():
    """Render the Live Scan tab."""
    st.markdown(
        '<div class="header-title">Live Scan</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="header-subtitle">Real-time penetration testing of target AI agent</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # Status bar
    col_status1, col_status2, col_status3, col_status4 = st.columns(4)
    with col_status1:
        target = st.session_state.target_url
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="font-size:1.1rem;">{target}</div>'
            f'<div class="metric-label">Target</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with col_status2:
        status_text = "Running..." if st.session_state.scan_running else (
            "Complete" if st.session_state.scan_complete else "Ready"
        )
        status_color = "#22c55e" if st.session_state.scan_complete else (
            "#2563eb" if st.session_state.scan_running else "#6b7280"
        )
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="font-size:1.1rem;color:{status_color};">'
            f"{status_text}</div>"
            f'<div class="metric-label">Status</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with col_status3:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="font-size:1.1rem;">'
            f'{len(st.session_state.findings_found)}</div>'
            f'<div class="metric-label">Findings</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with col_status4:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for fk in st.session_state.findings_found:
            f = FINDINGS.get(fk, {})
            sev = f.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        total_score = (
            severity_counts["Critical"] * 10
            + severity_counts["High"] * 7
            + severity_counts["Medium"] * 4
            + severity_counts["Low"] * 1
        )
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="font-size:1.1rem;color:#f59e0b;">'
            f'{total_score}</div>'
            f'<div class="metric-label">Risk Score</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Progress bar
    if st.session_state.scan_running:
        st.progress(st.session_state.scan_progress)
    elif st.session_state.scan_complete:
        st.progress(1.0)

    # Current action
    if st.session_state.current_step < len(DEMO_SEQUENCE):
        step = DEMO_SEQUENCE[st.session_state.current_step]
        if step["action"] == "show_progress":
            msg = step.get("msg", "")
            st.markdown(
                f'<div style="padding:8px 16px;background:#1a1f2c;border-radius:8px;'
                f'border-left:3px solid #2563eb;margin:8px 0;">'
                f'<span style="color:#9ca3af;">▶</span> '
                f'<span style="color:#e0e0e0;">{msg}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # Action buttons
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    with col_btn1:
        if st.button(
            "Start Scan" if not st.session_state.scan_running else "Scan Running...",
            disabled=st.session_state.scan_running,
            key="start_scan_btn",
        ):
            if st.session_state.demo_mode:
                st.session_state.scan_running = True
                st.session_state.scan_complete = False
                st.session_state.findings_found = []
                st.session_state.current_step = 0
                st.session_state.scan_progress = 0.0
                # Run the scan in a way streamlit can update
                run_demo_scan()
            else:
                # "Live" mode — not fully implemented for demo, fall back to demo
                st.session_state.demo_mode = True
                st.rerun()

    with col_btn2:
        if st.session_state.scan_running or st.session_state.scan_complete:
            if st.button("Reset", key="reset_scan_btn"):
                st.session_state.scan_running = False
                st.session_state.scan_complete = False
                st.session_state.findings_found = []
                st.session_state.current_step = 0
                st.session_state.scan_progress = 0.0
                st.rerun()

    # Live findings feed
    if st.session_state.findings_found:
        st.markdown("---")
        st.markdown("### Findings")
        for fk in st.session_state.findings_found:
            f = FINDINGS.get(fk, {})
            if f:
                st.markdown(finding_card_html(fk, f), unsafe_allow_html=True)

    # Initial state
    if not st.session_state.scan_running and not st.session_state.scan_complete:
        st.info(
            "Configure your scan in the sidebar and click 'Start Scan' to begin. "
            "Enable Demo Mode for a scripted walkthrough."
        )


def render_findings_dashboard():
    """Render the Findings Dashboard tab with charts and table."""
    st.markdown(
        '<div class="header-title">Findings Dashboard</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="header-subtitle">Aggregate analysis of all vulnerabilities discovered</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    if not st.session_state.findings_found:
        st.info(
            "No findings yet. Run a scan to populate the dashboard."
        )
        return

    # Data preparation
    findings_data = []
    for fk in st.session_state.findings_found:
        f = FINDINGS.get(fk, {})
        if f:
            findings_data.append(
                {
                    "ID": f.get("id", ""),
                    "Title": f.get("title", ""),
                    "Severity": f.get("severity", ""),
                    "Category": f.get("category", ""),
                    "OWASP": f.get("owasp", ""),
                }
            )

    # Severity counts
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    severity_counts = {}
    for s in severity_order:
        severity_counts[s] = sum(
            1 for fd in findings_data if fd["Severity"] == s
        )

    # Category counts
    category_counts = {}
    for fd in findings_data:
        cat = fd["Category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # --- Row 1: Charts ---
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        # Severity pie chart
        labels = []
        values = []
        colors = []
        for s in severity_order:
            count = severity_counts.get(s, 0)
            if count > 0:
                labels.append(f"{s} ({count})")
                values.append(count)
                colors.append(severity_color(s))

        if values:
            fig_pie = go.Figure(
                data=[
                    go.Pie(
                        labels=labels,
                        values=values,
                        marker=dict(colors=colors, line=dict(color="#0e1117", width=2)),
                        textinfo="label+percent",
                        textfont=dict(size=13, color="#e0e0e0"),
                        hole=0.5,
                        hoverinfo="label+value+percent",
                    )
                ]
            )
            fig_pie.update_layout(
                title=dict(
                    text="Findings by Severity",
                    font=dict(color="#e0e0e0", size=16),
                    x=0.5,
                ),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=50, b=20, l=20, r=20),
                height=320,
                showlegend=False,
            )
            st.plotly_chart(fig_pie, width='stretch')

    with col_chart2:
        # Category bar chart
        if category_counts:
            cats_sorted = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
            cat_labels = [c[0] for c in cats_sorted]
            cat_values = [c[1] for c in cats_sorted]

            fig_bar = go.Figure(
                data=[
                    go.Bar(
                        x=cat_values,
                        y=cat_labels,
                        orientation="h",
                        marker=dict(
                            color=["#dc2626", "#ea580c", "#ca8a04", "#2563eb", "#6b7280"][
                                : len(cat_labels)
                            ],
                            line=dict(color="#0e1117", width=1),
                        ),
                        text=cat_values,
                        textposition="outside",
                        textfont=dict(color="#e0e0e0", size=13),
                    )
                ]
            )
            fig_bar.update_layout(
                title=dict(
                    text="Findings by Category",
                    font=dict(color="#e0e0e0", size=16),
                    x=0.5,
                ),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=50, b=20, l=20, r=20),
                height=320,
                xaxis=dict(
                    title="Count",
                    tickfont=dict(color="#9ca3af"),
                    gridcolor="#2a2f3a",
                    showgrid=True,
                ),
                yaxis=dict(
                    tickfont=dict(color="#e0e0e0"),
                    gridcolor="#2a2f3a",
                ),
            )
            st.plotly_chart(fig_bar, width='stretch')

    # --- Row 2: Filter + Table ---
    st.markdown("### Finding Details")
    col_filter1, col_filter2, _ = st.columns([1, 1, 2])

    with col_filter1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=severity_order,
            default=severity_order,
            key="findings_severity_filter",
        )
    with col_filter2:
        categories_all = list(
            set(fd["Category"] for fd in findings_data)
        )
        category_filter = st.multiselect(
            "Filter by Category",
            options=categories_all,
            default=categories_all,
            key="findings_category_filter",
        )

    filtered_data = [
        fd
        for fd in findings_data
        if fd["Severity"] in severity_filter and fd["Category"] in category_filter
    ]

    if filtered_data:
        st.dataframe(
            filtered_data,
            width='stretch',
            hide_index=True,
            column_config={
                "ID": st.column_config.TextColumn("ID", width="small"),
                "Title": st.column_config.TextColumn("Title", width="large"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Category": st.column_config.TextColumn("Category", width="medium"),
                "OWASP": st.column_config.TextColumn("OWASP", width="medium"),
            },
        )

    # --- Row 3: Statistics ---
    st.markdown("### Summary Statistics")
    sum_cols = st.columns(5)
    for i, s in enumerate(severity_order):
        with sum_cols[i]:
            count = severity_counts.get(s, 0)
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value" style="font-size:1.5rem;color:{severity_color(s)};">'
                f"{count}</div>"
                f'<div class="metric-label">{s}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )


def render_cross_scan():
    """Render the Cross-Scan Analysis tab."""
    st.markdown(
        '<div class="header-title">Cross-Scan Analysis</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="header-subtitle">Elastic MCP-powered pattern correlation across scan history</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # Elastic integration stats card
    stats = ELASTIC_CORRELATION_STATS
    st.markdown(
        f'<div class="metric-card" style="text-align:left;">'
        f'<div style="font-size:1.2rem;font-weight:600;color:#a78bfa;">'
        f'Elastic MCP Threat Correlation</div>'
        f'<div style="display:flex;gap:40px;margin-top:16px;">'
        f'<div><span style="font-size:2rem;font-weight:700;color:#22c55e;">'
        f'{stats["total_scans_analyzed"]}</span>'
        f'<span style="color:#9ca3af;margin-left:6px;">Scans Analyzed</span></div>'
        f'<div><span style="font-size:2rem;font-weight:700;color:#f59e0b;">'
        f'{stats["similar_patterns_found"]}</span>'
        f'<span style="color:#9ca3af;margin-left:6px;">Similar Patterns Found</span></div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Systemic vulnerabilities
    st.markdown("### Systemic Vulnerabilities")
    st.markdown(
        "<p style='color:#9ca3af;'>Vulnerability patterns that appear across multiple scans — "
        "indicating architectural weaknesses rather than one-off bugs.</p>",
        unsafe_allow_html=True,
    )
    for sv in stats["systemic_vulnerabilities"]:
        st.markdown(
            f'<div class="systemic-card">'
            f'<p style="margin:0;">{sv}</p>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Recommendation
    st.markdown(
        f'<div style="background:#1a1f2c;border:1px solid #2a2f3a;border-radius:12px;'
        f'padding:16px;margin:12px 0;">'
        f'<strong style="color:#a78bfa;">Elastic MCP Recommendation:</strong><br>'
        f'<span style="color:#c0c8d8;">{stats["recommendation"]}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Trend chart
    st.markdown("### Vulnerability Trend Over Time")
    if SCAN_HISTORY:
        dates = [sh["date"] for sh in SCAN_HISTORY]
        trend_data = []
        for sh in SCAN_HISTORY:
            for cat, count in sh["categories"].items():
                trend_data.append(
                    {
                        "Date": sh["date"],
                        "Category": cat,
                        "Count": count,
                    }
                )

        # Group by date and sum
        import pandas as pd

        df_trend = pd.DataFrame(trend_data)
        fig_trend = px.area(
            df_trend,
            x="Date",
            y="Count",
            color="Category",
            title="Vulnerability Categories Across Scans",
            color_discrete_sequence=px.colors.qualitative.Bold,
        )
        fig_trend.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e0e0e0", size=12),
            title=dict(font=dict(color="#e0e0e0", size=16), x=0.5),
            xaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
            yaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
            legend=dict(font=dict(color="#e0e0e0")),
            margin=dict(t=50, b=20, l=20, r=20),
            height=400,
        )
        fig_trend.update_traces(mode="markers+lines")
        st.plotly_chart(fig_trend, width='stretch')

    # Total findings trend
    severity_timeline = []
    for sh in SCAN_HISTORY:
        for sev, count in sh["findings"].items():
            severity_timeline.append(
                {
                    "Date": sh["date"],
                    "Severity": sev,
                    "Count": count,
                    "Target": sh["target"],
                }
            )

    df_sev = pd.DataFrame(severity_timeline)
    fig_sev_trend = px.bar(
        df_sev,
        x="Date",
        y="Count",
        color="Severity",
        title="Severity Distribution Over Time",
        color_discrete_map={
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#ca8a04",
            "Low": "#2563eb",
            "Info": "#6b7280",
        },
        barmode="stack",
    )
    fig_sev_trend.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0", size=12),
        title=dict(font=dict(color="#e0e0e0", size=16), x=0.5),
        xaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
        yaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
        legend=dict(font=dict(color="#e0e0e0")),
        margin=dict(t=50, b=20, l=20, r=20),
        height=350,
    )
    st.plotly_chart(fig_sev_trend, width='stretch')

    # OWASP mapping
    st.markdown("### OWASP Top 10 for LLM Applications Mapping")
    st.markdown(
        "<p style='color:#9ca3af;'>Findings mapped to the OWASP framework for LLM application security.</p>",
        unsafe_allow_html=True,
    )

    for owasp_cat, findings_list in OWASP_MAPPINGS.items():
        with st.expander(f"{owasp_cat} ({len(findings_list)} finding(s))"):
            for fm in findings_list:
                fk = None
                for k, v in FINDINGS.items():
                    if v.get("id") == fm["finding"]:
                        fk = k
                        break
                if fk:
                    f = FINDINGS[fk]
                    st.markdown(
                        f"**{f.get('id')}: {f.get('title')}**  "
                        f"Severity: {f.get('severity')}",
                    )
                else:
                    st.markdown(f"**{fm['finding']}**: {fm['title']}")


def render_report():
    """Render the Report View tab."""
    st.markdown(
        '<div class="header-title">Security Report</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="header-subtitle">Professional penetration testing report — OWASP-compliant</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    if not st.session_state.findings_found:
        st.info(
            "No findings to report. Run a scan first."
        )
        return

    # Build report content
    target = st.session_state.target_url
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_findings = len(st.session_state.findings_found)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for fk in st.session_state.findings_found:
        f = FINDINGS.get(fk, {})
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Generate markdown
    report_lines = [
        "# AgentSentinel Security Scan Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Scan Date:** {scan_date}  ",
        f"**Total Findings:** {total_findings}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"AgentSentinel conducted a comprehensive security assessment of the AI agent at {target}. "
        f"A total of **{total_findings}** vulnerabilities were identified, including "
        f"**{severity_counts['Critical']} Critical**, **{severity_counts['High']} High**, "
        f"**{severity_counts['Medium']} Medium**, and "
        f"**{severity_counts['Info']} Informational** findings.",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = severity_counts.get(sev, 0)
        report_lines.append(f"| {sev} | {count} |")

    report_lines.extend(
        [
            "",
            "### Risk Score",
            "",
            f"**Total Risk Score:** "
            f"{severity_counts['Critical'] * 10 + severity_counts['High'] * 7 + severity_counts['Medium'] * 4 + severity_counts['Low'] * 1}",
            "",
            "---",
            "",
            "## Findings Detail",
            "",
        ]
    )

    for fk in st.session_state.findings_found:
        f = FINDINGS.get(fk, {})
        if not f:
            continue
        report_lines.extend(
            [
                f"### {f.get('id')}: {f.get('title')}",
                "",
                f"**Severity:** {f.get('severity')}  ",
                f"**Category:** {f.get('category')}  ",
                f"**OWASP:** {f.get('owasp')}  ",
                f"**CWE:** {f.get('cwe')}  ",
                "",
                "#### Description",
                "",
                f.get("description", ""),
                "",
                "#### Evidence",
                "",
                "```",
                f.get("evidence", ""),
                "```",
                "",
                "#### Steps to Reproduce",
                "",
                "```",
                f.get("reproduction", ""),
                "```",
                "",
                "#### Affected Component",
                "",
                f"`{f.get('affected_component', '')}`",
                "",
                "#### Remediation",
                "",
                f.get("remediation", ""),
                "",
                "---",
                "",
            ]
        )

    report_lines.extend(
        [
            "## OWASP Top 10 for LLM Applications Mapping",
            "",
            "| OWASP Category | Finding ID | Finding Title |",
            "|----------------|------------|---------------|",
        ]
    )

    for owasp_cat, findings_list in OWASP_MAPPINGS.items():
        for fm in findings_list:
            report_lines.append(
                f"| {owasp_cat} | {fm['finding']} | {fm['title']} |"
            )

    report_lines.extend(
        [
            "",
            "---",
            "",
            "## Recommendation",
            "",
            ELASTIC_CORRELATION_STATS.get("recommendation", ""),
            "",
            "---",
            "",
            "*Report generated by AgentSentinel — AI Agent Security Scanner*  ",
            f"*{scan_date}*",
        ]
    )

    report_md = "\n".join(report_lines)

    # Display report
    st.markdown("### Preview")
    st.markdown(
        f'<div style="background:#0d1117;border:1px solid #2a2f3a;border-radius:8px;'
        f'padding:20px;max-height:500px;overflow-y:auto;font-family:monospace;'
        f'font-size:0.8rem;color:#c0c8d8;white-space:pre-wrap;line-height:1.5;">'
        f'{report_md[:3000]}...'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Download button
    st.download_button(
        label="Download Full Report (Markdown)",
        data=report_md,
        file_name=f"agentsentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
        key="download_report_btn",
    )

    # OWASP mapping visualization
    st.markdown("### OWASP Mapping Visualization")
    owasp_data = []
    for owasp_cat, findings_list in OWASP_MAPPINGS.items():
        for fm in findings_list:
            owasp_data.append({"OWASP Category": owasp_cat, "Finding": fm["finding"]})

    if owasp_data:
        import pandas as pd
        df_owasp = pd.DataFrame(owasp_data)
        owasp_counts = df_owasp["OWASP Category"].value_counts().reset_index()
        owasp_counts.columns = ["OWASP Category", "Finding Count"]

        fig_owasp = px.bar(
            owasp_counts,
            x="OWASP Category",
            y="Finding Count",
            color="OWASP Category",
            color_discrete_sequence=px.colors.qualitative.Bold,
            title="OWASP Category Distribution",
        )
        fig_owasp.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e0e0e0", size=12),
            title=dict(font=dict(color="#e0e0e0", size=16), x=0.5),
            xaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
            yaxis=dict(tickfont=dict(color="#9ca3af"), gridcolor="#2a2f3a"),
            margin=dict(t=50, b=120, l=20, r=20),
            height=350,
        )
        fig_owasp.update_xaxes(tickangle=45)
        st.plotly_chart(fig_owasp, width='stretch')


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    # Logo / header
    st.markdown(
        '<div style="text-align:center;padding:16px 0 8px 0;">'
        '<span style="font-size:2.5rem;">⚠</span>'
        '<h1 style="font-size:1.6rem;margin:4px 0 0 0;background:linear-gradient(135deg,#2563eb,#7c3aed);'
        '-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">'
        "AgentSentinel</h1>"
        '<p style="color:#6b7280;font-size:0.75rem;margin:0;">AI Agent Security Scanner</p>'
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Target configuration
    st.markdown("### Target Configuration")
    st.text_input(
        "Target URL",
        value=st.session_state.target_url,
        key="target_url_input",
        placeholder="http://localhost:8765",
        label_visibility="collapsed",
    )

    # Demo mode toggle
    st.markdown("### Mode")
    demo_mode = st.checkbox(
        "Demo Mode",
        value=st.session_state.demo_mode,
        help="Run scripted demonstration sequence with predetermined findings",
        key="demo_mode_toggle",
    )
    st.session_state.demo_mode = demo_mode

    st.markdown("---")

    # Attack categories
    st.markdown("### Attack Categories")
    categories_all = [
        "Prompt Injection",
        "Tool Misuse",
        "Broken Access Control",
        "Code Injection",
        "Context Manipulation",
        "Information Disclosure",
        "Insecure Output Handling",
        "Data Validation",
    ]

    for cat in categories_all:
        default_checked = cat in st.session_state.selected_categories
        checked = st.checkbox(
            cat,
            value=default_checked,
            key=f"cat_{cat}",
        )
        if checked and cat not in st.session_state.selected_categories:
            st.session_state.selected_categories.append(cat)
        elif not checked and cat in st.session_state.selected_categories:
            st.session_state.selected_categories.remove(cat)

    st.markdown("---")

    # Start scan button
    start_disabled = st.session_state.scan_running
    if st.button(
        "Start Scan" if not start_disabled else "Scan in Progress...",
        disabled=start_disabled,
        key="sidebar_start_btn",
    ):
        st.session_state.target_url = st.session_state.target_url_input
        if st.session_state.demo_mode:
            st.session_state.scan_running = True
            st.session_state.scan_complete = False
            st.session_state.findings_found = []
            st.session_state.current_step = 0
            st.session_state.scan_progress = 0.0
            run_demo_scan()
        else:
            st.info(
                "Live mode requires a running victim agent. Enable Demo Mode "
                "for the scripted walkthrough."
            )

    if st.session_state.scan_running:
        st.markdown(
            f'<div style="text-align:center;padding:8px;margin-top:8px;">'
            f'<span style="color:#22c55e;font-size:0.85rem;">Scan active...</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Scan history
    st.markdown("### Scan History")
    for i, scan in enumerate(reversed(SCAN_HISTORY)):
        total = sum(scan["findings"].values())
        st.markdown(
            f'<div style="padding:8px;background:#1a1f2c;border-radius:6px;margin-bottom:6px;'
            f'border-left:3px solid #2563eb;">'
            f'<div style="font-size:0.85rem;color:#e0e0e0;font-weight:500;">'
            f"{scan['target']}</div>"
            f'<div style="font-size:0.75rem;color:#6b7280;">'
            f"{scan['date']} — {total} findings</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown(
        '<div style="text-align:center;padding:8px 0;">'
        '<p style="color:#6b7280;font-size:0.65rem;">'
        "Powered by Google Gemini & Elastic MCP<br>"
        "AgentSentinel v1.0"
        "</p>"
        "</div>",
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Main content — Tabs
# ---------------------------------------------------------------------------

tab_live, tab_findings, tab_cross, tab_report = st.tabs(
    ["Live Scan", "Findings Dashboard", "Cross-Scan Analysis", "Report"]
)

with tab_live:
    render_live_scan()

with tab_findings:
    render_findings_dashboard()

with tab_cross:
    render_cross_scan()

with tab_report:
    render_report()
