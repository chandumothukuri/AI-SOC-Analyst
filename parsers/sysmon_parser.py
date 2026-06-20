import json

def load_sysmon_logs(filepath):

    logs = []

    with open(filepath, "r") as f:

        for line in f:

            line = line.strip()

            if line:
                logs.append(json.loads(line))

    return logs