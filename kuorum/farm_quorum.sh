#!/usr/bin/env bash
# farm_quorum.sh — loop: run exp_quorum.py against all team targets, submit fresh flags.
cd /home/ctso/GEMASTIK/tarot
AD=/home/ctso/GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense
TICK=70
while true; do
    echo "=== $(date +%H:%M:%S) quorum sweep"
    while read -r HOST PORT LABEL; do
        [ -z "$HOST" ] && continue
        case "$HOST" in \#*) continue;; esac
        (F=$(timeout 25 python3 exp_quorum.py "$HOST" 23000 2>/dev/null); [ -n "$F" ] && echo "$F" >> quorum_flags.txt && echo "[+] $HOST: $F") &
    done < targets.txt
    wait
    bash submit_fresh_quorum.sh
    sleep $TICK
done
