def correlate_alerts(alerts):

    correlated = []

    alert_names = [

        alert.get(
            "alert_name",
            ""
        )

        for alert in alerts

        if alert

    ]

    if (

        "Encoded PowerShell Execution"
        in alert_names

        and

        "Suspicious Parent Child Process"
        in alert_names

    ):

        powershell_alert = None

        for alert in alerts:

            if (
                alert.get("alert_name")
                == "Suspicious PowerShell Activity"
            ):

                powershell_alert = alert
                break

        if powershell_alert is None:

            powershell_alert = alerts[0]

        correlated.append({

            "alert_name":
            "Multi-Stage Attack Detected",

            "host":
            powershell_alert.get(
                "host",
                "Unknown"
            ),

            "user":
            powershell_alert.get(
                "user",
                "Unknown"
            ),

            "severity":
            "Critical",

            "evidence":
            [

                "Encoded PowerShell Execution",
                "Suspicious Parent Child Process"

            ],

            "mitre_techniques":
            [

                "T1059.001",
                "T1059"

            ]

        })

    return correlated