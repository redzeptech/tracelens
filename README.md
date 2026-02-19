# TraceLens
Windows Event Log First Response & Triage Tool (EVTX)

> You don’t read logs. You see intent.

## What it does
TraceLens scans Windows Security logs and produces a quick triage summary:
- Failed logons (4625) / brute-force signals
- Successful logons (4624)
- Privileged logons (4672)
- New user creation (4720)
- Log clearing (1102)
- RDP logons (1149)

## Quick start
```bash
pip install -r requirements.txt
python tracelens.py scan ./evtx
RISK SCORE: 82/100 (HIGH)
- Possible brute force (RDP)
- Privileged logon detected
- Event logs cleared (1102)
Report: reports/incident_YYYY-MM-DD.html

