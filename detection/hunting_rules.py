def detect_suspicious_powershell(event):

    if event.get("EventID") != 1:
        return None

    image = event.get(
        "Image",
        ""
    ).lower()

    command_line = event.get(
        "CommandLine",
        ""
    ).lower()

    if "powershell" not in image:
        return None

    indicators = [

        "-enc",
        "-encodedcommand",
        "iex",
        "invoke-expression",
        "downloadstring",
        "webclient",
        "downloadfile"

    ]

    for indicator in indicators:

        if indicator in command_line:

            return {

                "alert_name":
                "Suspicious PowerShell Activity",

                "host":
                event.get(
                    "Computer",
                    "Unknown"
                ),

                "user":
                event.get(
                    "User",
                    "Unknown"
                ),

                "severity":
                "High",

                "command_line":
                command_line,

                "mitre_tactic":
                "Execution",

                "mitre_technique":
                "T1059.001"

            }

    return None