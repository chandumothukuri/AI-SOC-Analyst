from parsers.evtx_parser import read_evtx

events = read_evtx(
    "raw_logs/sysmon.evtx"
)

count = 0

for event in events:

    if event.get("EventID") == 3:

        count += 1

        print("\nNETWORK EVENT\n")

        print(
            "Image:",
            event.get("Image")
        )

        print(
            "DestinationIp:",
            event.get("DestinationIp")
        )

        print(
            "DestinationPort:",
            event.get("DestinationPort")
        )

        if count == 5:
            break

print(
    f"\nNetwork Events Found: {count}"
)