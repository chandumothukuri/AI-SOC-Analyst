from parsers.evtx_parser import read_evtx

from detection.hunting_rules import (
    detect_suspicious_powershell
)

events = read_evtx(
    "raw_logs/sysmon.evtx"
)

count = 0

for event in events:

    alert = detect_suspicious_powershell(
        event
    )

    if alert:

        count += 1

        print(
            "\nALERT FOUND\n"
        )

        print(
            alert
        )

print(
    f"\nTotal Hunting Alerts: {count}"
)