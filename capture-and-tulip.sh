#!/usr/bin/env bash
# =========================================================================
#  Baca trafik service milikmu di Tulip, BEGITU SSH terbuka.
#  SSH ke sebuah service terbuka setelah kamu capture >=1 flag di service itu.
#
#  Pakai:
#     ./capture-and-tulip.sh <your-ip> <ssh-port> [ingest-port]
#  Contoh (service :30000 -> SSH :30022, ingest Tulip default 9999):
#     ./capture-and-tulip.sh 10.13.37.5 30022 9999
#
#  Password SSH ada di halaman Challenges (SSH creds). Pasang sshpass biar
#  tak diminta berulang:  sudo apt install sshpass
#  lalu set:  export SSHPASS='passwordmu'   dan jalankan script ini.
# =========================================================================
set -u
IP="${1:?butuh your-ip}"; SSHP="${2:?butuh ssh-port}"; INGEST="${3:-9999}"
USER="ctfuser"

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
[ -n "${SSHPASS:-}" ] && command -v sshpass >/dev/null && SSH="sshpass -e $SSH"

# tcpdump di box (tanpa root -> mungkin butuh cap; kalau 'permission denied',
# pakai rute waf.py di RUNBOOK.md §4, atau fallback log di dalam /app).
REMOTE="tcpdump -i any -n --immediate-mode -s 65535 -U -w - 'tcp and not port 22'"

echo "[*] stream $USER@$IP:$SSHP  ->  Tulip ingest :$INGEST (Ctrl-C untuk stop)"
$SSH "$USER@$IP" -p "$SSHP" "$REMOTE" | nc localhost "$INGEST"
