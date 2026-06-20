from reports.incident_report import (
    generate_incident_report
)


def create_report(alert, ai_result):

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

    whois_data = {
        "owner": "Unknown",
        "asn": "Unknown"
    }

    criticality = "Unknown"

    report = generate_incident_report(
        alert,
        mitre,
        geo,
        abuse,
        vt,
        whois_data,
        criticality,
        ai_result
    )

    return report