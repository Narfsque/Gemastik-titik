#!/usr/bin/env bash
# submit_fresh_quorum.sh — submit unaccepted flags from quorum_flags.txt
cd /home/ctso/GEMASTIK/tarot
AD=/home/ctso/GEMASTIK/GEMASTIK/toolkit/ctf-toolkit/attack_defense
TOKEN=$(grep -m1 Authorization $AD/config.py | grep -o 'Bearer [^"]*')
touch accepted_quorum.log
sort -u accepted_quorum.log > /tmp/acc_q.txt
grep -o 'GEMASTIK{[^}]*}' quorum_flags.txt 2>/dev/null | sort -u > /tmp/qf.txt
comm -23 /tmp/qf.txt /tmp/acc_q.txt > /tmp/qf_new.txt
OK=0
while read -r f; do
    [ -z "$f" ] && continue
    R=$(curl -s -m 10 -X POST https://gemastik19-finals.siberlab.id/api/flag \
        -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
        -d "{\"flag\":\"$f\"}")
    case "$R" in
        *successfully*|*accepted*) echo "$f" >> accepted_quorum.log; OK=$((OK+1));;
    esac
done < /tmp/qf_new.txt
echo "$(date +%H:%M:%S) quorum accepted_new=$OK total=$(wc -l < accepted_quorum.log)"
