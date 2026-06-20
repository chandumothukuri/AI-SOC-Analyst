from parsers.evtx_parser import read_evtx

events = read_evtx(
    "raw_logs/sysmon.evtx"
)

print(
    f"Total Events: {len(events)}"
)

for event in events:

    if event["EventID"] == 1:

        print("\n" + "=" * 60)

        print(
            f"Event ID: {event['EventID']}"
        )

        print(
            event["RawXML"][:3000]
        )

        break