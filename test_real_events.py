from parsers.evtx_parser import read_evtx

events = read_evtx(
    "raw_logs/sysmon.evtx"
)

for event in events:

    if event["EventID"] == 1:

        print("\nPROCESS CREATION EVENT\n")

        print(
            "Image:",
            event.get("Image")
        )

        print(
            "CommandLine:",
            event.get("CommandLine")
        )

        print(
            "User:",
            event.get("User")
        )

        print(
            "ParentImage:",
            event.get("ParentImage")
        )

        break