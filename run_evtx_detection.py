from parsers.evtx_parser import read_evtx

from detection.detection_engine import (
    detect_powershell,
    detect_malware,
    detect_failed_logins,
    detect_malicious_ip,
    detect_data_exfiltration
)

from detection.hunting_rules import (
    detect_suspicious_powershell,
    detect_lolbins,
    detect_suspicious_parent_child
)

from detection.correlation_engine import (
    correlate_alerts
)

from detection.alert_writer import save_alert


events = read_evtx(
    "raw_logs/sysmon.evtx"
)

print(
    f"Loaded {len(events)} events"
)

alert_count = 0

all_alerts = []

for event in events:

    alerts = [

        # Detection Engine
        detect_powershell(event),
        detect_malware(event),
        detect_failed_logins(event),
        detect_malicious_ip(event),
        detect_data_exfiltration(event),

        # Hunting Rules
        detect_suspicious_powershell(event),
        detect_lolbins(event),
        detect_suspicious_parent_child(event)

    ]

    for alert in alerts:

        if alert:

            all_alerts.append(alert)

            path = save_alert(alert)

            alert_count += 1

            print(
                f"[ALERT] {alert['alert_name']} -> {path}"
            )

# Correlation Engine

correlated_alerts = correlate_alerts(
    all_alerts
)

for alert in correlated_alerts:

    all_alerts.append(alert)

    path = save_alert(alert)

    alert_count += 1

    print(
        f"[CORRELATED] {alert['alert_name']} -> {path}"
    )

print(
    f"\nTotal Alerts Generated: {alert_count}"
)