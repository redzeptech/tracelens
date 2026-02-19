import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from modules.parse_windows_xml import iter_events_from_xml

WATCH = {4624, 4625, 4672, 4720, 1102, 1149}

WEIGHTS = {
    4625: 30,
    1149: 20,
    4672: 20,
    1102: 35,
    4720: 15,
}

def clamp(n, lo=0, hi=100):
    return max(lo, min(hi, n))

def risk_label(score):
    if score >= 80: return "HIGH"
    if score >= 50: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"

def parse_time(ts):
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except:
        return None

def scan(path, html=False):
    p = Path(path)
    if not p.exists():
        print("[!] Path not found:", p)
        return 2

    xml_files = [p] if p.is_file() else list(p.rglob("*.xml"))
    if not xml_files:
        print("[!] No XML found.")
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
                user = data.get("TargetUserName", "")
                ip = data.get("IpAddress", "")

                if user and user != "-":
                    fail_users[user] += 1
                if ip and ip not in ("-", "::1", "127.0.0.1"):
                    fail_ips[ip] += 1

    bf_count = 0
    bf_window_min = 10
    bf_threshold = 20

    if fail_times:
        latest = max(fail_times)
        window_start = latest - timedelta(minutes=bf_window_min)
        bf_count = sum(1 for t in fail_times if t >= window_start)

    bruteforce = bf_count >= bf_threshold

    score = 0
    if counts[1149] > 0: score += WEIGHTS[1149]
    if counts[4672] > 0: score += WEIGHTS[4672]
    if counts[1102] > 0: score += WEIGHTS[1102]
    if counts[4720] > 0: score += WEIGHTS[4720]
    if bruteforce: score += WEIGHTS[4625]

    score = clamp(score)
    label = risk_label(score)

    lines = []
    def out(x=""):
        print(x)
        lines.append(x)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out(f"[+] TraceLens scan @ {now}")
    out(f"[+] Target: {p.resolve()}")
    out("")
    out(f"RISK SCORE: {score}/100 ({label})")
    out(f"Total events parsed: {total_events}")
    out("Event counts:")
    for eid in sorted(WATCH):
        if counts[eid]:
            out(f"- {eid}: {counts[eid]}")
    out("")

    if fail_times:
        status = "SUSPECTED" if bruteforce else "NOT SUSPECTED"
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

    out("")
    out("[i] Next: HTML report + MITRE mapping + timeline export")

    if html:
        base = Path(__file__).resolve().parent
        report_dir = base / "reports"
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / "tracelens_report.html"

        findings = "\n".join(lines)

        html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>TraceLens Report</title>
<style>
body {{ background:#0f172a; color:#e5e7eb; font-family:Segoe UI, Arial; padding:30px; }}
.card {{ background:#111827; padding:24px; border-radius:16px; max-width:900px; margin:auto; }}
.score {{ font-size:42px; font-weight:bold; margin: 10px 0 18px 0; }}
.low {{ color:#22c55e; }}
.medium {{ color:#f59e0b; }}
.high {{ color:#ef4444; }}
pre {{ background:#020617; padding:14px; border-radius:12px; white-space:pre-wrap; }}
</style>
</head>
<body>
<div class="card">
<h1>TraceLens Report</h1>
<div class="score {label.lower()}">Risk Score: {score}/100 ({label})</div>
<pre>{findings}</pre>
</div>
</body>
</html>
"""
        report_path.write_text(html_doc, encoding="utf-8")
        print(f"[+] HTML report written: {report_path.resolve()}")

    return 0

def main():
    parser = argparse.ArgumentParser(prog="tracelens")
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("scan")
    s.add_argument("path")
    s.add_argument("--html", action="store_true")

    args = parser.parse_args()
    if args.cmd == "scan":
        raise SystemExit(scan(args.path, html=args.html))
    parser.print_help()

if __name__ == "__main__":
    main()
