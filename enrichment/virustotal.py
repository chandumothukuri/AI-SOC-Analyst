import requests

from config import VT_API_KEY


def check_virustotal(ip):

    url = (
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            url,
            headers=headers
        )

        if response.status_code != 200:

            return {
                "detections": 0,
                "status": "API Error"
            }

        data = response.json()

        stats = data["data"]["attributes"][
            "last_analysis_stats"
        ]

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        total = malicious + suspicious

        return {

            "detections": total,

            "status": (
                "Malicious"
                if total > 0
                else "Clean"
            )

        }

    except Exception:

        return {

            "detections": 0,

            "status": "Error"

        }