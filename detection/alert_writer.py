import json
import os

def save_alert(alert):

    os.makedirs("alerts", exist_ok=True)

    filename = (
        alert["alert_name"]
        .replace(" ", "_")
        .lower()
        + ".json"
    )

    filepath = os.path.join(
        "alerts",
        filename
    )

    with open(filepath, "w") as f:

        json.dump(
            alert,
            f,
            indent=4
        )

    return filepath