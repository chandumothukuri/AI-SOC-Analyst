def get_whois(ip):

    whois_db = {

        "185.220.101.45": {
            "owner": "TOR Network",
            "asn": "AS60729",
            "country": "Germany"
        },

        "10.0.0.5": {
            "owner": "Internal Network",
            "asn": "Private",
            "country": "Internal"
        },

        "192.168.1.10": {
            "owner": "Corporate Network",
            "asn": "Private",
            "country": "Internal"
        },

        "192.168.1.25": {
            "owner": "HR Network",
            "asn": "Private",
            "country": "Internal"
        },

        "10.10.10.15": {
            "owner": "File Server Network",
            "asn": "Private",
            "country": "Internal"
        }
    }

    return whois_db.get(
        ip,
        {
            "owner": "Unknown",
            "asn": "Unknown",
            "country": "Unknown"
        }
    )