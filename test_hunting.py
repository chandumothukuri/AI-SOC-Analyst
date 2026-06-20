from parsers.evtx_parser import read_evtx

from detection.hunting_rules import (
    detect_suspicious_powershell,
    detect_lolbins,
    detect_suspicious_parent_child
)

events = read_evtx(
    "raw_logs/sysmon.evtx"
)

powershell_count = 0
lolbin_count = 0
parent_child_count = 0

for event in events:

    ps_alert = detect_suspicious_powershell(
        event
    )

    if ps_alert:

        powershell_count += 1

        print("\n[POWERSHELL ALERT]\n")

        print(ps_alert)

    lolbin_alert = detect_lolbins(
        event
    )

    if lolbin_alert:

        lolbin_count += 1

        print("\n[LOLBIN ALERT]\n")

        print(lolbin_alert)

    parent_alert = detect_suspicious_parent_child(
        event
    )

    if parent_alert:

        parent_child_count += 1

        print("\n[PARENT-CHILD ALERT]\n")

        print(parent_alert)

print(
    f"\nPowerShell Alerts: {powershell_count}"
)

print(
    f"LOLBin Alerts: {lolbin_count}"
)

print(
    f"Parent-Child Alerts: {parent_child_count}"
)