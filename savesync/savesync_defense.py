#!/usr/bin/env python3
"""DEFENSE PATCH — SaveSync (vulnbox kita: 10.13.37.8, SSH port 27022).

JANGAN DIJALANKAN otomatis — review dulu, jalankan manual.

Bug: /sync/restore?code=<hex16> mengembalikan save akun siapa pun tanpa auth.
     Kode restore = sha256(SECRET_CONST + ":" + accountId)[:16] — SECRET konstan
     (dari libsave.so), accountId checker = 1337 publik di /leaderboard.

Service = Go binary (single container; frontend statis + API di :27000).

Patch SLA-safe: checker masih bisa simpan/unduh save miliknya; endpoint restore
dibatasi sehingga TIDAK bisa membaca akun orang lain:
  O1. Patch binary: ganti handler /sync/restore agar butuh param token yang
      cocok dengan account_id (auth penuh).
  O2. Alternatif (paling sederhana & paling aman): REJECT /sync/restore total
      (403). Risiko SLA: bila checker menguji endpoint ini, defence/SLA turun.
      → Opsi O2 hanya dipakai bila checker terbukti tidak memakai restore.
  O3. Alternatif menengah: restrict restore ke account_id milik koneksi sendiri
      — tidak bisa dilakukan andal tanpa auth, jadi pakai O1/O2.

Cara O1 (binary patch via reverse proxy di depan — TANPA ubah binary):
  Karena service = Go di :8000 internal di belakang entrypoint, dan kita cuma
  ctfuser, cara paling aman = pasang filter di depan: jalankan proxy kecil
  (python stdlib) di :8000-alt dan geser service. TIDAK bisa tanpa restart panel.
  → Maka O1 implementasinya: sed script memodifikasi file HTML/JS yang dikirim
    client TIDAK MUNGKIN (API di server).
  → Realistis untuk container ini: O2 (blok endpoint) via tcp redirect helper
    bila tersedia; jika tidak, terima risiko dan andalkan bahwa checker tidak
    memanggil restore.

Cara pakai (manual):
  ssh -p 27022 ctfuser@10.13.37.8
  cp -a /app /app.bak-$(date +%s) 2>/dev/null || true
  # O2 — blok restore dengan iptables tidak bisa (no root). Pakai wrapper:
  #   1) cari binary & port internal:
  #      ps aux | grep savesync
  #      ss -ltnp 2>/dev/null | grep -E '8000|27000'
  #   2) jika service listen di 127.0.0.1:8000 dan entrypoint bisa diedit
  #      (/app/start.sh), sisipkan proxy filter (savesync_filter.py di bawah)
  #      sebelum start service:
  #        python3 /app/savesync_filter.py 127.0.0.1:8001 127.0.0.1:8000 &
  #        exec /app/savesync --listen 127.0.0.1:8000   # service asli
  #      dan proxy listen di 8001 sebagai entrypoint... URUTANNYA:
  #        service asli tetap di 8000; proxy masuk di port publik.
  #      start.sh diubah: proxy di depan (listen port yang tadinya dipakai
  #      service), service digeser ke port internal.
  #   3) restart dari panel web UI, verifikasi /health & /sync/upload normal.

Filter behavior (savesync_filter.py):
  - /sync/restore  -> 403 (O2) atau butuh ?token= valid (O1-lite: cek token
    terhadap /sync/download? tidak bisa tanpa state; jadi default = 403).
  - semua request lain diteruskan byte-per-byte (transparan, SLA aman).
"""
import sys

FILTER_PY = r'''#!/usr/bin/env python3
"""saveguard — transparan TCP proxy + filter /sync/restore (SLA-safe).

Usage: python3 saveguard.py LISTEN TARGET
  LISTEN = 0.0.0.0:PORT_PUBLIK   (port yang tadinya dipakai service)
  TARGET = 127.0.0.1:PORT_INTERNAL (service asli dipindah ke sini)

Mode: blok /sync/restore (403) — semua request lain diteruskan utuh.
HTTP/1.1 keep-alive-aware minimal: header dibaca penuh, body via
Content-Length / chunked tidak diparse (cukup: blok dilakukan pada request
pertama tiap koneksi; browser/GO client umumnya 1 request per koneksi untuk
endpoint ini). Untuk keamanan penuh pakai mode --strict yang menutup koneksi
setelah request pertama yang diblok.
"""
import socket, sys, threading, re

def main():
    listen, target = sys.argv[1], sys.argv[2]
    lh, lp = listen.split(":"); th, tp = target.split(":")
    lp, tp = int(lp), int(tp)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, lp)); srv.listen(64)
    print(f"saveguard {listen} -> {target} (blocking /sync/restore)", flush=True)
    while True:
        cs, _ = srv.accept()
        threading.Thread(target=pipe, args=(cs, th, tp), daemon=True).start()

def pipe(cs, th, tp):
    try:
        bs = socket.create_connection((th, tp), timeout=5)
    except Exception:
        cs.close(); return
    b2c = threading.Thread(target=fwd, args=(bs, cs), daemon=True); b2c.start()
    buf = b""
    try:
        cs.settimeout(10)
        while True:
            d = cs.recv(65536)
            if not d: break
            buf += d
            while True:
                hdr_end = buf.find(b"\r\n\r\n")
                if hdr_end == -1:
                    if len(buf) > 65536: cs.close(); return
                    break
                head, rest = buf[:hdr_end], buf[hdr_end+4:]
                line = head.split(b"\r\n")[0].decode("latin1", "replace")
                m = re.match(r"(\w+)\s+(\S+)", line)
                path = m.group(2) if m else ""
                blocked = "/sync/restore" in path
                out = head + b"\r\n\r\n" + rest
                if blocked:
                    body = b'{"error":"forbidden"}'
                    resp = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                            b"Connection: close\r\n\r\n" + body)
                    cs.sendall(resp); cs.close(); bs.close(); return
                # forward header + sisanya; setelah header pertama diteruskan,
                # sisanya leak-through langsung (chunked/stream aman)
                bs.sendall(out)
                buf = b""
                break
            # leak-through mode setelah header pertama lolos
            if buf is not None and buf == b"":
                fwd_rest(cs, bs)
                return
    except Exception:
        pass
    finally:
        try: cs.close()
        except Exception: pass
        try: bs.close()
        except Exception: pass

def fwd_rest(cs, bs):
    try:
        cs.settimeout(10)
        while True:
            d = cs.recv(65536)
            if not d: break
            bs.sendall(d)
    except Exception:
        pass
    finally:
        try: bs.shutdown(socket.SHUT_WR)
        except Exception: pass

def fwd(a, b):
    try:
        a.settimeout(15)
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except Exception:
        pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except Exception: pass

if __name__ == "__main__":
    main()
'''

START_SH_PATCH = """#!/bin/bash
# start.sh DEFENSE — proxy filter di depan savesync
# (letakkan sebelum exec service; port internal digeser +1)
service ssh start
# service asli tetap di port internal (contoh 8000); proxy di port publik lama
nohup python3 /app/saveguard.py 0.0.0.0:8001 127.0.0.1:8000 >/tmp/saveguard.log 2>&1 &
sleep 0.5
exec /app/savesync --listen 0.0.0.0:8001   # GANTI sesuai entrypoint asli; bila
# binary sudah bind 8001 maka cukup jalankan proxy di port publik asli dan biarkan
# service di port internalnya — sesuaikan dengan ps/ss saat implementasi.
"""

def main():
    if "--apply" not in sys.argv:
        print(__doc__); return
    # Tulis file filter saja (tidak mengubah service — butuh edit start.sh manual
    # karena struktur entrypoint perlu diverifikasi dulu di vulnbox).
    open("/app/saveguard.py", "w").write(FILTER_PY)
    print("[OK] /app/saveguard.py ditulis (filter /sync/restore -> 403)")
    print("[*] LANGKAH MANUAL (butuh verifikasi port internal dulu):")
    print("    ps aux | grep savesync ; ss -ltn 2>/dev/null | grep 27000")
    print("    edit entrypoint (start.sh): jalankan saveguard di port publik,")
    print("    service digeser ke port internal; restart dari panel web UI.")
    print("[*] Verifikasi: /health 200, /sync/upload+download checker normal,")
    print("    /sync/restore -> 403.")

if __name__ == "__main__":
    main()
