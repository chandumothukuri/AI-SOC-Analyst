def check_abuse_score(ip):

    abuse_database = {

        "185.220.101.45": {
            "abuse_score": 95,
            "reputation": "Malicious"
        },

        "192.168.1.10": {
            "abuse_score": 5,
            "reputation": "Clean"
        },

        "192.168.1.25": {
            "abuse_score": 2,
            "reputation": "Clean"
        },

        "10.10.10.15": {
            "abuse_score": 1,
            "reputation": "Clean"
        }
    }

    return abuse_database.get(
        ip,
        {
            "abuse_score": 0,
            "reputation": "Unknown"
        }
    )