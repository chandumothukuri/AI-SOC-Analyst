def generate_report(alert, risk_score, mitre):

    report = f"""
==============================
SOC INCIDENT REPORT
==============================

Alert Name : {alert['alert_name']}
Host       : {alert['host']}
User       : {alert['user']}
Severity   : {alert['severity']}
Risk Score : {risk_score}/100

MITRE ATT&CK
------------
Tactic      : {mitre['tactic']}
Technique   : {mitre['technique']}

Assessment
----------
Potential security event detected.

Recommendation
--------------
Investigate the affected system.
Review logs and user activity.
Escalate if malicious activity is confirmed.

==============================
"""

    return report