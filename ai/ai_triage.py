def analyze_alert(alert, mitre, geo, abuse, vt):

    summary = (
        f"{alert['alert_name']} detected on "
        f"{alert['host']} by user {alert['user']}."
    )

    threat_assessment = "Unknown"

    confidence = "Low"

    verdict = "False Positive"

    if abuse["abuse_score"] > 80 or vt["detections"] > 20:

        threat_assessment = (
            "External threat indicators suggest malicious activity."
        )

        confidence = "High"

        verdict = "True Positive"

    elif alert["severity"] == "High":

        threat_assessment = (
            "High severity alert requiring investigation."
        )

        confidence = "Medium"

        verdict = "Suspicious"

    recommendations = [

        "Review endpoint activity",

        "Inspect network connections",

        "Check user behavior",

        "Escalate if malicious activity confirmed"
    ]

    return {

        "summary": summary,

        "threat_assessment": threat_assessment,

        "confidence": confidence,

        "verdict": verdict,

        "recommendations": recommendations,

        "mitre_tactic": mitre["tactic"],

        "mitre_technique": mitre["technique"]
    }