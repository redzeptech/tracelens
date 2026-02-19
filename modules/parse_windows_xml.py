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
    for d in elem.findall(".//e:EventData/e:Data", namespaces=NS):
        name = d.get("Name")
        if name:
            data[name] = (d.text or "").strip()
    if not data:
        for d in elem.findall(".//EventData/Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return data

def _findtext_any(elem, paths: list[str]) -> str:
    for xp in paths:
        r = elem.findtext(xp, namespaces=NS)
        if r:
            return r
    for xp in paths:
        r = elem.findtext(xp.replace("e:", ""), namespaces=None)
        if r:
            return r
    return ""

def _iter_event_fragments(file_path: Path, chunk_size: int = 1024 * 1024) -> Iterable[str]:
    start_tag = "<Event"
    end_tag = "</Event>"
    buf = ""

    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf += chunk

            while True:
                s = buf.find(start_tag)
                if s == -1:
                    buf = buf[-len(start_tag):]
                    break

                e = buf.find(end_tag, s)
                if e == -1:
                    buf = buf[s:]
                    break

                frag = buf[s : e + len(end_tag)]
                buf = buf[e + len(end_tag):]
                yield frag

def iter_events_from_xml(xml_file: str | Path) -> Iterable[WinEvent]:
    xml_file = Path(xml_file)

    for frag in _iter_event_fragments(xml_file):
        try:
            elem = etree.fromstring(
                frag.encode("utf-8"),
                parser=etree.XMLParser(recover=True, huge_tree=True),
            )

            event_id_txt = _findtext_any(elem, ["e:System/e:EventID", "./System/EventID"])
            if not event_id_txt:
                continue
            event_id = int(event_id_txt)

            tc = elem.find(".//e:System/e:TimeCreated", namespaces=NS)
            if tc is None:
                tc = elem.find(".//System/TimeCreated")
            time_created = tc.get("SystemTime") if tc is not None else ""

            computer = _findtext_any(elem, ["e:System/e:Computer", "./System/Computer"])
            channel = _findtext_any(elem, ["e:System/e:Channel", "./System/Channel"])

            provider_node = elem.find(".//e:System/e:Provider", namespaces=NS)
            if provider_node is None:
                provider_node = elem.find(".//System/Provider")
            provider = provider_node.get("Name") if provider_node is not None else ""

            record_id_txt = _findtext_any(elem, ["e:System/e:EventRecordID", "./System/EventRecordID"])
            record_id = int(record_id_txt) if record_id_txt.isdigit() else None

            data = _event_data_map(elem)

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
        except Exception:
            continue
