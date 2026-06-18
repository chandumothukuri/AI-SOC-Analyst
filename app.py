import json
import os

from reports.report_generator import generate_report

mitre_mapping = {
    "Encoded PowerShell Execution": {
        "technique": "T1059.001",
        "tactic": "Execution"
    },
    "Multiple Failed Logins": {
        "technique": "T1110",
        "tactic": "Credential Access"
    }
}
alert_folder = "alerts"
output_folder = "output"

os.makedirs(output_folder, exist_ok=True)

for file in os.listdir(alert_folder):

    if file.endswith(".json"):

        with open(os.path.join(alert_folder, file), "r") as f:
            alert = json.load(f)

        severity = alert["severity"]

        if severity == "High":
            risk_score = 90
        elif severity == "Medium":
            risk_score = 60
        else:
            risk_score = 30

        mitre = mitre_mapping.get(
            alert["alert_name"],
            {
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        )

        report = generate_report(alert, risk_score, mitre)

        report_name = file.replace(".json", "_report.txt")
        report_path = os.path.join(output_folder, report_name)

        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write(report)

        print(f"\n[+] Report Saved: {report_name}")