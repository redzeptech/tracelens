import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

from modules.parse_windows_xml import iter_events_from_xml

WATCH = {4624, 4625, 4672, 4720, 1102, 1149}

WEIGHTS = {
    4625: 30,   # only if burst suspected
    1149: 20,
    4672: 20,
    1102: 35,
    4720: 15,
}

def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))

def risk_label(score: int) -> str:
    if score >= 80: return "HIGH"
    if score >= 50: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"

def parse_time(ts: str):
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def export_evtx_windows(evtx: Path, out_xml: Path) -> None:
    ps = Path("tools") / "export_evtx_windows.ps1"
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps),
           "-EvtxPath", str(evtx), "-OutXml", str(out_xml)]
    subprocess.check_call(cmd)

def scan(path: str):
    p = Path(path)
    if not p.exists():
        print(f"[!] Path not found: {p}")
        return 2

    # gather XML files
    xml_files = []
    if p.is_file() and p.suffix.lower() == ".xml":
        xml_files = [p]
    elif p.is_dir():
        xml_files = list(p.rglob("*.xml"))

    # if no XML and Windows + EVTX provided, export to XML
    if not xml_files and platform.system().lower() == "windows":
        evtx_files = []
        if p.is_file() and p.suffix.lower() == ".evtx":
            evtx_files = [p]
        elif p.is_dir():
            evtx_files = list(p.rglob("*.evtx"))

        if evtx_files:
            out_dir = Path("output")
            out_dir.mkdir(exist_ok=True)
            for evtx in evtx_files[:3]:
                out_xml = out_dir / f"{evtx.stem}.xml"
                print(f"[+] Exporting: {evtx.name} -> {out_xml}")
                export_evtx_windows(evtx, out_xml)
                xml_files.append(out_xml)

    if not xml_files:
        print("[!] No XML found. Provide a .xml export or (on Windows) an .evtx file/folder.")
        return 2

    counts = {eid: 0 for eid in WATCH}
    total_events = 0


    fail_times = []
    fail_users = Counter()
    fail_ips = Counter()

    for xf in xml_files:
        for ev in iter_events_from_xml(xf):
            total_events += 1

            if ev.event_id in WATCH:
                counts[ev.event_id] += 1

            if ev.event_id == 4625:
                t = parse_time(ev.time_created)
                if t:
                    fail_times.append(t)
                data = ev.data or {}
                u = data.get("TargetUserName") or ""
                ip = data.get("IpAddress") or ""
                if u and u != "-":
                    fail_users[u] += 1
                if ip and ip not in ("-", "::1", "127.0.0.1"):
                    fail_ips[ip] += 1

    # brute-force heuristic
    bf_window_min = 10
    bf_threshold = 20
    bf_count = 0

    if fail_times:
        latest = max(fail_times)
        window_start = latest - timedelta(minutes=bf_window_min)
        bf_count = sum(1 for t in fail_times if t >= window_start)

    bruteforce_suspected = bf_count >= bf_threshold

    # score (only count 4625 if burst suspected)
    score = 0
    if counts.get(1149, 0) > 0: score += WEIGHTS[1149]
    if counts.get(4672, 0) > 0: score += WEIGHTS[4672]
    if counts.get(1102, 0) > 0: score += WEIGHTS[1102]
    if counts.get(4720, 0) > 0: score += WEIGHTS[4720]
    if bruteforce_suspected: score += WEIGHTS[4625]

    score = clamp(score)
    label = risk_label(score)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[+] TraceLens scan @ {now}")
    print(f"[+] Target: {p.resolve()}")
    print("")
    print(f"RISK SCORE: {score}/100 ({label})")
    print(f"Total events parsed: {total_events}")
    print("Event counts:")
    for eid in sorted(WATCH):
        c = counts.get(eid, 0)
        if c:
            print(f"- {eid}: {c}")

    print("")
    if fail_times:
    status = "SUSPECTED" if bruteforce_suspected else "NOT SUSPECTED"
    out(f"Brute-force: {status} | 4625 in last {bf_window_min} min = {bf_count} (threshold {bf_threshold})")

    if fail_users:
        u, c = fail_users.most_common(1)[0]
        out(f"Top targeted user: {u} ({c})")
    else:
        out("Top targeted user: (not present in events)")

    if fail_ips:
        ip, c = fail_ips.most_common(1)[0]
        out(f"Top source IP: {ip} ({c})")
    else:
        out("Top source IP: (not present in events)")


            else:
    print("Top source IP: (not present in events)")


    print("")
    print("[i] Next: HTML report + MITRE mapping + timeline export")
    return 0

def main():
    parser = argparse.ArgumentParser(prog="tracelens", description="Windows EVTX triage tool")
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Scan a folder containing EVTX/XML")
    s.add_argument("path", help="Path to EVTX/XML file or folder")

    args = parser.parse_args()
    if args.cmd == "scan":
        raise SystemExit(scan(args.path))
    parser.print_help()

if __name__ == "__main__":
    main()
