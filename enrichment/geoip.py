def get_geoip(ip):

    geo_database = {

        "185.220.101.45": {
            "country": "Germany",
            "city": "Berlin",
            "risk": "Suspicious"
        },

        "192.168.1.10": {
            "country": "Internal",
            "city": "Corporate Network",
            "risk": "Trusted"
        },

        "192.168.1.25": {
            "country": "Internal",
            "city": "HR Network",
            "risk": "Trusted"
        },

        "10.10.10.15": {
            "country": "Internal",
            "city": "Data Center",
            "risk": "Trusted"
        }
    }

    return geo_database.get(
        ip,
        {
            "country": "Unknown",
            "city": "Unknown",
            "risk": "Unknown"
        }
    )