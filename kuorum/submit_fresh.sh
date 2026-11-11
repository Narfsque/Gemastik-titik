#!/usr/bin/env bash
# submit_fresh.sh — submit only fresh flags from flags.queue; append accepted to accepted.log
cd /home/ctso/GEMASTIK/tarot
AD=/home/ctso/GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense
TOKEN=$(grep -m1 Authorization $AD/config.py | grep -o 'Bearer [^"]*')
grep -o 'GEMASTIK{[^}]*}' flags.queue | sort -u > /tmp/q_all.txt
# skip ones already accepted
sort -u accepted.log 2>/dev/null > /tmp/acc.txt || touch /tmp/acc.txt
comm -23 /tmp/q_all.txt /tmp/acc.txt > /tmp/q_new.txt
OK=0; ALR=0; INV=0
while read -r f; do
    [ -z "$f" ] && continue
    R=$(curl -s -m 10 -X POST https://gemastik19-finals.siberlab.id/api/flag \
        -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
        -d "{\"flag\":\"$f\"}")
    case "$R" in
        *successfully*) echo "$f" >> accepted.log; OK=$((OK+1));;
        *already*) ALR=$((ALR+1));;
        *) INV=$((INV+1));;
    esac
done < /tmp/q_new.txt
echo "$(date +%H:%M:%S) ok=$OK already=$ALR invalid/expired=$INV total_accepted=$(wc -l < accepted.log)"
