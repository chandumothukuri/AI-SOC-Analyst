def detect_powershell(log):

    command = log.get(
        "CommandLine",
        ""
    ).lower()

    if "-enc" in command:

        return {

            "alert_name":
            "Encoded PowerShell Execution",

            "host":
            log["Computer"],

            "user":
            log["User"],

            "source_ip":
            "192.168.1.10",

            "severity":
            "High"
        }

    return None
def detect_failed_logins(log):

    if (
        log.get("EventID") == 4625
        and
        log.get("FailedAttempts", 0) >= 5
    ):

        return {

            "alert_name":
            "Multiple Failed Logins",

            "host":
            log["Computer"],

            "user":
            log["User"],

            "source_ip":
            "10.0.0.5",

            "severity":
            "Medium"
        }

    return None
def detect_malware(log):

    image = log.get(
        "Image",
        ""
    ).lower()

    if "malware.exe" in image:

        return {

            "alert_name":
            "Malware Execution Detected",

            "host":
            log["Computer"],

            "user":
            log["User"],

            "source_ip":
            "192.168.1.25",

            "severity":
            "High"
        }

    return None
def detect_malicious_ip(log):

    suspicious_ips = [
        "185.220.101.45"
    ]

    if (
        log.get("EventID") == 3
        and
        log.get("DestinationIp") in suspicious_ips
    ):

        return {

            "alert_name":
            "Malicious IP Communication",

            "host":
            log["Computer"],

            "user":
            log["User"],

            "source_ip":
            log["DestinationIp"],

            "severity":
            "High"
        }

    return None
def detect_data_exfiltration(log):

    if (
        log.get("EventID") == 3
        and
        log.get("BytesSent", 0) > 10000000
    ):

        return {

            "alert_name":
            "Data Exfiltration Attempt",

            "host":
            log["Computer"],

            "user":
            log["User"],

            "source_ip":
            "10.10.10.15",

            "severity":
            "High"
        }

    return None