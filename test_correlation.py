from detection.correlation_engine import correlate_alerts

alerts = [

    {

        "alert_name":
        "Encoded PowerShell Execution"

    },

    {

        "alert_name":
        "Suspicious Parent Child Process"

    }

]

results = correlate_alerts(
    alerts
)

for alert in results:

    print("\nCORRELATED ALERT\n")

    print(alert)

print(
    f"\nTotal Correlated Alerts: {len(results)}"
)