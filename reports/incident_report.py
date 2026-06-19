# reports/incident_report.py

def generate_incident_report(
    alert,
    mitre,
    geo,
    abuse,
    vt,
    whois_data,
    criticality,
    ai_result
):

    report = f"""
=========================================
INCIDENT REPORT
=========================================

EXECUTIVE SUMMARY
-----------------------------------------
{ai_result['summary']}

ALERT DETAILS
-----------------------------------------
Alert Name : {alert['alert_name']}
Host       : {alert['host']}
User       : {alert['user']}
Severity   : {alert['severity']}

THREAT INTELLIGENCE
-----------------------------------------
Country    : {geo['country']}
City       : {geo['city']}
Risk       : {geo['risk']}

Abuse Score: {abuse['abuse_score']}
Reputation : {abuse['reputation']}

VT Detects : {vt['detections']}
VT Status  : {vt['status']}

WHOIS Owner: {whois_data['owner']}
ASN        : {whois_data['asn']}

ASSET CRITICALITY
-----------------------------------------
{criticality}

MITRE ATT&CK
-----------------------------------------
Tactic     : {mitre['tactic']}
Technique  : {mitre['technique']}

AI TRIAGE
-----------------------------------------
Verdict    : {ai_result['verdict']}
Confidence : {ai_result['confidence']}

Threat Assessment:
{ai_result['threat_assessment']}

RECOMMENDED ACTIONS
-----------------------------------------
"""

    for action in ai_result["recommendations"]:
        report += f"\n• {action}"

    return report