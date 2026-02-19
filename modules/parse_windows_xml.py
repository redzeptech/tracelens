from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Optional, Dict
from pathlib import Path
from lxml import etree

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

@dataclass
class WinEvent:
    event_id: int
    time_created: str
    computer: str
    channel: str
    provider: str
    record_id: Optional[int] = None
    data: Dict[str, str] | None = None
    xml_path: Optional[str] = None

def _event_data_map(elem) -> Dict[str, str]:
    data = {}
    for d in elem.findall("e:EventData/e:Data", namespaces=NS):
        name = d.get("Name")
        if name:
            data[name] = (d.text or "").strip()
    return data

def iter_events_from_xml(xml_file: str | Path) -> Iterable[WinEvent]:
    xml_file = Path(xml_file)

    # IMPORTANT: don't filter by tag here; some exports vary in namespaces.
    context = etree.iterparse(
        str(xml_file),
        events=("end",),
        recover=True,
        huge_tree=True,
    )

    for _, elem in context:
        try:
            # Accept both namespaced and non-namespaced Event tags
            if not (elem.tag == "Event" or str(elem.tag).endswith("}Event")):
                continue

            # Try namespaced paths first
            event_id_txt = elem.findtext("e:System/e:EventID", namespaces=NS)
            if not event_id_txt:
                # Fallback without namespace
                event_id_txt = elem.findtext("./System/EventID")

            if not event_id_txt:
                continue
            event_id = int(event_id_txt)

            tc = elem.find("e:System/e:TimeCreated", namespaces=NS)
            if tc is None:
                tc = elem.find("./System/TimeCreated")
            time_created = tc.get("SystemTime") if tc is not None else ""

            computer = elem.findtext("e:System/e:Computer", namespaces=NS) or elem.findtext("./System/Computer") or ""
            channel = elem.findtext("e:System/e:Channel", namespaces=NS) or elem.findtext("./System/Channel") or ""
            provider_node = elem.find("e:System/e:Provider", namespaces=NS) or elem.find("./System/Provider")
            provider = provider_node.get("Name") if provider_node is not None else ""

            record_id_txt = elem.findtext("e:System/e:EventRecordID", namespaces=NS) or elem.findtext("./System/EventRecordID")
            record_id = int(record_id_txt) if record_id_txt and record_id_txt.isdigit() else None

            data = _event_data_map(elem)
            if not data:
                # Fallback: non-namespaced EventData
                data = {}
                for d in elem.findall("./EventData/Data"):
                    name = d.get("Name")
                    if name:
                        data[name] = (d.text or "").strip()

            yield WinEvent(
                event_id=event_id,
                time_created=time_created,
                computer=computer,
                channel=channel,
                provider=provider,
                record_id=record_id,
                data=data,
                xml_path=str(xml_file),
            )
        finally:
            elem.clear()
            while elem.getprevious() is not None:
                del elem.getparent()[0]
