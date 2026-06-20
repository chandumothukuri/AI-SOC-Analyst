import time
import os
import json

from detection.detection_engine import (
    detect_powershell,
    detect_failed_logins,
    detect_malware,
    detect_malicious_ip,
    detect_data_exfiltration
)

from detection.alert_writer import save_alert

from automation.auto_triage import run_ai_triage
from automation.auto_report import create_report
from automation.auto_pdf import create_pdf


print("SOC Monitor Started...")


if os.path.exists("raw_logs/sysmon.log"):

    processed_lines = sum(
        1 for _ in open(
            "raw_logs/sysmon.log",
            "r",
            encoding="utf-8"
        )
    )

else:

    processed_lines = 0


while True:

    with open(
        "raw_logs/sysmon.log",
        "r",
        encoding="utf-8"
    ) as f:

        lines = f.readlines()

    new_lines = lines[processed_lines:]

    for line in new_lines:

        try:

            log = json.loads(
                line.strip()
            )

            alerts = [

                detect_powershell(log),

                detect_failed_logins(log),

                detect_malware(log),

                detect_malicious_ip(log),

                detect_data_exfiltration(log)

            ]

            for alert in alerts:

                if alert:

                    # Save Alert
                    path = save_alert(alert)

                    # AI Triage
                    ai_result = run_ai_triage(
                        alert
                    )

                    # Incident Report
                    report = create_report(
                        alert,
                        ai_result
                    )

                    # PDF Report
                    pdf_file = create_pdf(
                        report,
                        alert["alert_name"]
                    )

                    print(
                        f"[ALERT] {alert['alert_name']}"
                    )

                    print(
                        f"[JSON] {path}"
                    )

                    print(
                        f"[PDF] {pdf_file}"
                    )

        except Exception as e:

            print(
                f"Error processing log: {e}"
            )

    processed_lines = len(lines)

    time.sleep(5)