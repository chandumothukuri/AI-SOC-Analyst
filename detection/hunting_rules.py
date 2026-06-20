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

                "image":
                event.get(
                    "Image",
                    ""
                ),

                "command_line":
                event.get(
                    "CommandLine",
                    ""
                ),

                "mitre_tactic":
                "Execution",

                "mitre_technique":
                "T1059.001"

            }

    return None


def detect_lolbins(event):

    if event.get("EventID") != 1:
        return None

    image = event.get(
        "Image",
        ""
    ).lower()

    command_line = event.get(
        "CommandLine",
        ""
    )

    lolbins = [

        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe"

    ]

    for binary in lolbins:

        if binary in image:

            return {

                "alert_name":
                "LOLBin Execution Detected",

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
                "Medium",

                "image":
                event.get(
                    "Image",
                    ""
                ),

                "command_line":
                command_line,

                "mitre_tactic":
                "Defense Evasion",

                "mitre_technique":
                "T1218"

            }

    return None
def detect_suspicious_parent_child(event):

    if event.get("EventID") != 1:
        return None

    image = event.get(
        "Image",
        ""
    ).lower()

    parent = event.get(
        "ParentImage",
        ""
    ).lower()

    suspicious_pairs = [

        (
            "cmd.exe",
            "powershell.exe"
        ),

        (
            "winword.exe",
            "powershell.exe"
        ),

        (
            "excel.exe",
            "cmd.exe"
        ),

        (
            "excel.exe",
            "powershell.exe"
        )

    ]

    for parent_proc, child_proc in suspicious_pairs:

        if (
            parent_proc in parent
            and child_proc in image
        ):

            return {

                "alert_name":
                "Suspicious Parent Child Process",

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

                "parent_process":
                event.get(
                    "ParentImage",
                    ""
                ),

                "child_process":
                event.get(
                    "Image",
                    ""
                ),

                "mitre_tactic":
                "Execution",

                "mitre_technique":
                "T1059"

            }

    return None