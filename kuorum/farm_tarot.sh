#!/usr/bin/env bash
# farm_tarot.sh — loop: sweep tarot flags every TICK, submit immediately.
# Usage: nohup bash farm_tarot.sh >/tmp/farm_tarot.log 2>&1 &
cd "$(dirname "$0")"
AD=~/GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense
TICK=75   # < round 180s; sweep 24 targets ~40s
while true; do
    echo "=== $(date +%H:%M:%S) sweep"
    python3 sweep_tarot.py
    # only fresh flags: seen-dedup against server via submit script
    TOKEN=$(grep -m1 Authorization $AD/config.py | grep -o 'Bearer [^"]*')
    while read -r f; do
        [ -z "$f" ] && continue
        R=$(curl -s -m 10 -X POST https://gemastik19-finals.siberlab.id/api/flag \
            -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
            -d "{\"flag\":\"$f\"}")
        case "$R" in
            *"already"*) ;;
            *"successfully"*|*"accepted"*) echo "$(date +%H:%M:%S) ACCEPT $f" >> accepted.log ;;
        esac
    done < <(grep -o 'GEMASTIK{[^}]*}' flags.uniq | sort -u)
    sleep $TICK
done
