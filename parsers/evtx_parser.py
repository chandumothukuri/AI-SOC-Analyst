from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


def read_evtx(file_path):

    events = []

    with Evtx(file_path) as log:

        for record in log.records():

            try:

                root = ET.fromstring(
                    record.xml()
                )

                namespace = {
                    "e":
                    "http://schemas.microsoft.com/win/2004/08/events/event"
                }

                event_id = root.find(
                    ".//e:EventID",
                    namespace
                )

                computer = root.find(
                    ".//e:Computer",
                    namespace
                )

                event = {

                    "EventID":
                    int(event_id.text)
                    if event_id is not None
                    else 0,

                    "Computer":
                    computer.text
                    if computer is not None
                    else "Unknown"

                }

                for data in root.findall(
                    ".//e:EventData/e:Data",
                    namespace
                ):

                    name = data.get(
                        "Name"
                    )

                    if name:

                        event[name] = (
                            data.text
                            if data.text
                            else ""
                        )

                events.append(
                    event
                )

            except Exception:

                pass

    return events