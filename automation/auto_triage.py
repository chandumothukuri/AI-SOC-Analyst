from ai.ai_triage import analyze_alert


def run_ai_triage(alert):

    mitre = {
        "tactic": "Unknown",
        "technique": "Unknown"
    }

    geo = {
        "country": "Unknown",
        "city": "Unknown",
        "risk": "Unknown"
    }

    abuse = {
        "abuse_score": 0,
        "reputation": "Unknown"
    }

    vt = {
        "detections": 0,
        "status": "Unknown"
    }

    result = analyze_alert(
        alert,
        mitre,
        geo,
        abuse,
        vt
    )

    return result