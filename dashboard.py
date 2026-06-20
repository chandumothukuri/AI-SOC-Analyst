import streamlit as st
import json
import os
import pandas as pd

from enrichment.geoip import get_geoip
from enrichment.abuseipdb import check_abuse_score
from enrichment.virustotal import check_virustotal
from enrichment.whois_lookup import get_whois
from enrichment.asset_criticality import get_asset_criticality

from ai.ai_triage import analyze_alert
from reports.incident_report import generate_incident_report
from reports.pdf_report import generate_pdf_report
# =====================================

# PAGE CONFIG
# =====================================

st.set_page_config(
    page_title="AI SOC Analyst",
    page_icon="🛡️",
    layout="wide"
)

# =====================================
# HEADER
# =====================================

st.title("🛡️ AI SOC Analyst Dashboard")
st.markdown("### Automated Alert Triage & Incident Reporting")

alert_folder = "alerts"

alerts = []
alerts_raw = []

# =====================================
# MITRE ATT&CK MAPPING
# =====================================

mitre_mapping = {

    "Encoded PowerShell Execution": {
        "technique": "T1059.001",
        "tactic": "Execution"
    },

    "Multiple Failed Logins": {
        "technique": "T1110",
        "tactic": "Credential Access"
    },

    "Malicious IP Communication": {
        "technique": "T1071",
        "tactic": "Command and Control"
    },

    "Malware Execution Detected": {
        "technique": "T1204",
        "tactic": "Execution"
    },

    "Data Exfiltration Attempt": {
        "technique": "T1041",
        "tactic": "Exfiltration"
    }
}

# =====================================
# LOAD ALERTS
# =====================================

for file in os.listdir(alert_folder):

    if file.endswith(".json"):

        with open(os.path.join(alert_folder, file), "r") as f:

            alert = json.load(f)

        alerts_raw.append(alert)

        severity = alert["severity"]

        if severity == "High":
            risk_score = 90

        elif severity == "Medium":
            risk_score = 60

        else:
            risk_score = 30

        mitre = mitre_mapping.get(
            alert["alert_name"],
            {
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        )

        alerts.append({
            "Alert": alert["alert_name"],
            "Host": alert["host"],
            "User": alert["user"],
            "Source IP": alert["source_ip"],
            "Severity": severity,
            "Risk Score": risk_score,
            "MITRE Tactic": mitre["tactic"],
            "MITRE Technique": mitre["technique"]
        })

df = pd.DataFrame(alerts)

# =====================================
# SIDEBAR
# =====================================

st.sidebar.title("SOC Controls")

st.sidebar.success("Dashboard Online")

if st.sidebar.button("🔄 Refresh"):
    st.rerun()

# =====================================
# METRICS
# =====================================

total_alerts = len(df)

high_alerts = len(df[df["Severity"] == "High"])

medium_alerts = len(df[df["Severity"] == "Medium"])

avg_risk = round(df["Risk Score"].mean())

st.header("📊 SOC Metrics")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Alerts", total_alerts)
c2.metric("High Alerts", high_alerts)
c3.metric("Medium Alerts", medium_alerts)
c4.metric("Average Risk", avg_risk)

st.divider()

# =====================================
# CHARTS
# =====================================

col1, col2 = st.columns(2)

with col1:

    st.subheader("📈 Alert Severity Distribution")

    severity_count = df["Severity"].value_counts().reset_index()

    severity_count.columns = ["Severity", "Count"]

    st.bar_chart(
        severity_count.set_index("Severity")
    )
with col2:

    st.subheader("📊 Risk Scores")

    risk_df = df.set_index("Alert")

    st.bar_chart(risk_df["Risk Score"])

st.divider()

# =====================================
# ALERT TABLE
# =====================================

st.header("📋 Alert Overview")

st.dataframe(
    df,
    use_container_width=True
)

st.divider()

# =====================================
# MITRE ATT&CK SUMMARY
# =====================================

st.header("🎯 MITRE ATT&CK Summary")

mitre_counts = df["MITRE Tactic"].value_counts()

st.bar_chart(mitre_counts)

st.divider()
# =====================================
# ALERT INVESTIGATION
# =====================================

st.header("🚨 Alert Investigation")

for idx, row in df.iterrows():

    with st.expander(f"🔍 {row['Alert']}"):

        # Alert Details
        st.subheader("Alert Details")

        st.write(f"**Host:** {row['Host']}")
        st.write(f"**User:** {row['User']}")
        st.write(f"**Source IP:** {row['Source IP']}")
        st.write(f"**Severity:** {row['Severity']}")
        st.write(f"**Risk Score:** {row['Risk Score']}/100")

        # MITRE
        st.subheader("MITRE ATT&CK")

        st.write(f"**Tactic:** {row['MITRE Tactic']}")
        st.write(f"**Technique:** {row['MITRE Technique']}")

        # Threat Intel
        geo = get_geoip(row["Source IP"])
        abuse = check_abuse_score(row["Source IP"])
        vt = check_virustotal(row["Source IP"])
        whois_data = get_whois(row["Source IP"])
        criticality = get_asset_criticality(row["Host"])

        alert_data = {
            "alert_name": row["Alert"],
            "host": row["Host"],
            "user": row["User"],
            "severity": row["Severity"]
        }

        mitre_data = {
            "tactic": row["MITRE Tactic"],
            "technique": row["MITRE Technique"]
        }

        ai_result = analyze_alert(
            alert_data,
            mitre_data,
            geo,
            abuse,
            vt
        )

        report = generate_incident_report(
            alert_data,
            mitre_data,
            geo,
            abuse,
            vt,
            whois_data,
            criticality,
            ai_result
        )

        # Threat Intelligence
        st.subheader("🌍 Threat Intelligence")

        col_a, col_b, col_c = st.columns(3)

        with col_a:
            st.info(
                f"""
Country: {geo['country']}

City: {geo['city']}

Risk: {geo['risk']}
"""
            )

        with col_b:
            st.warning(
                f"""
Abuse Score: {abuse['abuse_score']}

Reputation: {abuse['reputation']}
"""
            )

        with col_c:
            st.error(
                f"""
Detections: {vt['detections']}

Status: {vt['status']}
"""
            )

        # WHOIS
        st.subheader("🌐 WHOIS Information")

        col_d, col_e = st.columns(2)

        with col_d:
            st.info(
                f"""
Owner: {whois_data['owner']}

ASN: {whois_data['asn']}
"""
            )

        with col_e:
            st.info(
                f"""
Country: {whois_data['country']}
"""
            )

        # Asset Criticality
        st.subheader("🏢 Asset Criticality")

        if criticality == "Critical":
            st.error(f"Critical Asset: {criticality}")

        elif criticality == "High":
            st.warning(f"Asset Criticality: {criticality}")

        elif criticality == "Medium":
            st.info(f"Asset Criticality: {criticality}")

        else:
            st.success(f"Asset Criticality: {criticality}")

        # AI Analysis
        st.subheader("🤖 AI Analysis")

        st.success(
            f"""
Executive Summary:

{ai_result['summary']}

Threat Assessment:

{ai_result['threat_assessment']}
"""
        )

        col_ai1, col_ai2 = st.columns(2)

        with col_ai1:
            st.metric(
                "Confidence",
                ai_result["confidence"]
            )

        with col_ai2:
            st.metric(
                "Verdict",
                ai_result["verdict"]
            )

        st.write("### Recommended Actions")

        for action in ai_result["recommendations"]:
            st.write(f"• {action}")

        # Incident Report
        st.subheader("📄 Incident Report")

        st.code(report)
        # Save TXT Report
        txt_filename = (
            row["Alert"]
            .replace(" ", "_")
            .lower()
            + "_incident_report.txt"
        )

        if st.button(
            f"💾 Save TXT - {row['Alert']}",
            key=f"txt_{row['Alert']}_{idx}"
        ):

            with open(
                f"output/{txt_filename}",
                "w",
                encoding="utf-8"
            ) as f:
                f.write(report)

            st.success(f"Saved: {txt_filename}")

        # Generate PDF Report
        pdf_filename = (
            row["Alert"]
            .replace(" ", "_")
            .lower()
            + "_incident_report.pdf"
        )

        if st.button(
            f"📄 Generate PDF - {row['Alert']}",
            key=f"pdf_{row['Alert']}_{idx}"
        ):

            generate_pdf_report(
                report,
                f"output/{pdf_filename}"
            )

            st.success(
                f"PDF Created: {pdf_filename}"
            )

        # Analyst Recommendation
        st.subheader("Analyst Recommendation")

        if row["Severity"] == "High":

            st.error(
                """
Immediate investigation required.

• Review endpoint activity
• Check process execution
• Verify network connections
• Escalate if confirmed malicious
"""
            )

        elif row["Severity"] == "Medium":

            st.warning(
                """
Monitor activity.

• Review authentication logs
• Validate user behavior
• Investigate anomalies
"""
            )

        else:

            st.success(
                """
Low priority event.

• Continue monitoring
"""
            )

st.divider()
# =====================================
# FOOTER
# =====================================

st.success("✅ AI SOC Analyst Dashboard Running")