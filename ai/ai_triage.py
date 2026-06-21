def analyze_alert(alert, mitre, geo, abuse, vt):

    summary = (
        f"Alert '{alert['alert_name']}' observed on "
        f"{alert['host']} by user {alert['user']}."
    )

    threat_assessment = (
        "No strong threat indicators identified."
    )

    confidence = "Low"

    verdict = "False Positive"

    # Critical Correlated Attacks

    if alert["severity"] == "Critical":

        threat_assessment = (
            "Multiple detections were correlated into a potential attack chain."
        )

        confidence = "High"

        verdict = "True Positive"

    # External Threat Intelligence

    elif (

        abuse["abuse_score"] > 80

        or

        vt["detections"] > 20

    ):

        threat_assessment = (
            "External threat intelligence indicates malicious activity."
        )

        confidence = "High"

        verdict = "True Positive"

    # High Severity Alerts

    elif alert["severity"] == "High":

        threat_assessment = (
            "High severity alert requiring analyst investigation."
        )

        confidence = "Medium"

        verdict = "Suspicious"

    # Medium Severity Alerts

    elif alert["severity"] == "Medium":

        threat_assessment = (
            "Potentially suspicious activity observed."
        )

        confidence = "Medium"

        verdict = "Needs Review"

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