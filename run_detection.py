from parsers.sysmon_parser import load_sysmon_logs

from detection.detection_engine import (
    detect_powershell,
    detect_failed_logins,
    detect_malware,
    detect_malicious_ip,
    detect_data_exfiltration
)

from detection.alert_writer import save_alert


logs = load_sysmon_logs(
    "raw_logs/sysmon.log"
)

for log in logs:

    alerts = [

        detect_powershell(log),

        detect_failed_logins(log),

        detect_malware(log),

        detect_malicious_ip(log),

        detect_data_exfiltration(log)

    ]

    for alert in alerts:

        if alert:

            path = save_alert(alert)

            print(
                f"Alert saved: {path}"
            )