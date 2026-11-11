#!/usr/bin/env python3
"""savesync farm — sweep all teams for round flags + submit fresh ones.
Runs forever, tick ~70s. Start: nohup python3 farm_savesync.py > /tmp/farm_savesync.log 2>&1 &
"""
import sys, os, time, json, subprocess, urllib.request

HERE = "/home/ctso/GEMASTIK/tarot"
sys.path.insert(0, HERE)
from exp_savesync import read_targets, one  # one() returns (host, [flags])
import concurrent.futures

AD = os.path.expanduser("~/GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense")

def get_token():
    for line in open(os.path.join(AD, "config.py")):
        if "Authorization" in line:
            import re
            m = re.search(r'Bearer [^"]+', line)
            if m:
                return m.group(0)
    return ""

TOKEN = get_token()

def submit(flag):
    req = urllib.request.Request(
        "https://gemastik19-finals.siberlab.id/api/flag",
        data=json.dumps({"flag": flag}).encode(),
        headers={"Authorization": TOKEN, "Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(req, timeout=10).read().decode()
    except Exception as e:
        return str(e)

accepted = set()
p = os.path.join(HERE, "accepted_savesync.log")
if os.path.exists(p):
    accepted = set(l.strip() for l in open(p) if l.strip())

TICK = 70
while True:
    t0 = time.time()
    targets = read_targets()
    found = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for host, flags in ex.map(one, targets):
            found.update(flags)
    ok = 0
    for f in found - accepted:
        r = submit(f)
        if "successfully" in r or "accepted" in r:
            accepted.add(f)
            ok += 1
    with open(p, "a") as fh:
        for f in found & accepted:
            pass
    # rewrite ledger
    with open(p, "w") as fh:
        for f in sorted(accepted):
            fh.write(f + "\n")
    print(f"{time.strftime('%H:%M:%S')} found={len(found)} accepted_new={ok} total={len(accepted)} ({time.time()-t0:.0f}s)", flush=True)
    time.sleep(max(5, TICK - (time.time() - t0)))
