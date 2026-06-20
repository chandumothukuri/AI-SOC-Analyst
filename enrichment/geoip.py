import requests


def get_geoip(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
        )

        data = response.json()

        return {

            "country": data.get(
                "country",
                "Unknown"
            ),

            "city": data.get(
                "city",
                "Unknown"
            ),

            "risk": (
                "External"
                if data.get("country")
                else "Unknown"
            )

        }

    except Exception:

        return {

            "country": "Unknown",

            "city": "Unknown",

            "risk": "Unknown"

        }