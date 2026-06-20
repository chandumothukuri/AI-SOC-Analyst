import requests

from config import ABUSEIPDB_API_KEY


def check_abuse_score(ip):

    url = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    headers = {

        "Accept": "application/json",

        "Key": ABUSEIPDB_API_KEY

    }

    params = {

        "ipAddress": ip,

        "maxAgeInDays": 90

    }

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params
        )

        if response.status_code != 200:

            return {

                "abuse_score": 0,

                "reputation": "API Error"

            }

        data = response.json()

        score = data["data"][
            "abuseConfidenceScore"
        ]

        return {

            "abuse_score": score,

            "reputation": (
                "Malicious"
                if score > 50
                else "Clean"
            )

        }

    except Exception:

        return {

            "abuse_score": 0,

            "reputation": "Error"

        }