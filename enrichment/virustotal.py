def check_virustotal(ip):

    vt_database = {

        "185.220.101.45": {
            "detections": 48,
            "status": "Malicious"
        },

        "192.168.1.10": {
            "detections": 0,
            "status": "Clean"
        },

        "192.168.1.25": {
            "detections": 0,
            "status": "Clean"
        },

        "10.10.10.15": {
            "detections": 0,
            "status": "Clean"
        }
    }

    return vt_database.get(
        ip,
        {
            "detections": 0,
            "status": "Unknown"
        }
    )