from parsers.evtx_parser import read_evtx

from detection.detection_engine import (
    detect_powershell,
    detect_malware,
    detect_failed_logins,
    detect_malicious_ip,
    detect_data_exfiltration
)

from detection.alert_writer import save_alert


events = read_evtx(
    "raw_logs/sysmon.evtx"
)

print(
    f"Loaded {len(events)} events"
)

alert_count = 0

for event in events:

    alerts = [

        detect_powershell(event),

        detect_malware(event),

        detect_failed_logins(event),

        detect_malicious_ip(event),

        detect_data_exfiltration(event)

    ]

    for alert in alerts:

        if alert:

            path = save_alert(alert)

            alert_count += 1

            print(
                f"[ALERT] {alert['alert_name']} -> {path}"
            )

print(
    f"\nTotal Alerts Generated: {alert_count}"
)