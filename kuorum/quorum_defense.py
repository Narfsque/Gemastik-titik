#!/usr/bin/env python3
"""DEFENSE PATCH — Quorum (vulnbox kita: 10.13.37.8, SSH port 23022).

JANGAN DIJALANKAN otomatis — review dulu, jalankan manual.

Bug: /audit mem-bocorkan share STATIS tanpa batas kumulatif → polinom
     derajat 24 direkonstruksi penuh via Lagrange → C0/C1 → z dipalsukan.

Patch SLA-safe (endpoint tetap hidup untuk checker):
  P1. audit kumulatif: maksimal T indeks BERBEDA sepanjang masa proses.
      Checker legitimate tidak butuh audit > t share, jadi SLA aman.
  P2. (penguat) share berputar per-round: _C0/_C1 di-derive ulang dari
      /flag.txt saat pertama kali flag berubah — mahal; P1 saja sudah cukup
      karena penyerang butuh 25 share dan kini maksimal 24.

Cara pakai (manual):
  ssh -p 23022 ctfuser@10.13.37.8
  cp -a /app /app.bak-$(date +%s)          # backup dulu
  python3 quorum_defense.py --apply
  # restart dari panel web UI, verifikasi: /params 200, /sign sah tetap jalan
"""
import sys, shutil, time

LEDGER = "/app/ledger.py"
APP = "/app/app.py"

def patch_ledger(src):
    # tambah pelacak indeks ter-audit + batas kumulatif T
    if "_AUDITED" in src:
        print("[SKIP] ledger sudah dipatch"); return src
    anchor = 'X = [pow((1 + _OFF[i]) % L, L - 2, L) for i in range(N)]'
    assert anchor in src, "ledger anchor not found"
    src = src.replace(anchor, anchor + '\n\n_AUDITED = set()\n_AUDIT_CAP = T', 1)
    return src

def patch_app(src):
    old = """    indices = sorted(set(int(i) for i in indices))
    if any(i < 0 or i >= ledger.N for i in indices):
        return Response("index out of range", status=400)
    if len(indices) > ledger.T:
        return Response("audit is capped at t shares", status=403)"""
    new = """    indices = sorted(set(int(i) for i in indices))
    if any(i < 0 or i >= ledger.N for i in indices):
        return Response("index out of range", status=400)
    if len(indices) > ledger.T:
        return Response("audit is capped at t shares", status=403)
    if len(ledger._AUDITED | set(indices)) > ledger._AUDIT_CAP:
        return Response("audit budget exhausted", status=429)
    ledger._AUDITED.update(indices)"""
    assert old in src, "app.py audit pattern not found"
    return src.replace(old, new, 1)

PATCHES = [
    (LEDGER, patch_ledger),
    (APP, patch_app),
]

def main():
    if "--apply" not in sys.argv:
        print(__doc__); return
    for path, fn in PATCHES:
        src = open(path).read()
        try:
            out = fn(src)
        except AssertionError as e:
            print(f"[SKIP] {path}: {e}"); continue
        bak = f"{path}.bak-{int(time.time())}"
        shutil.copy2(path, bak)
        open(path, "w").write(out)
        print(f"[OK] {path} (backup: {bak})")
    print("[*] Restart dari panel, verifikasi /params & /sign normal.")

if __name__ == "__main__":
    main()
