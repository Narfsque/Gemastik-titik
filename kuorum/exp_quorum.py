#!/usr/bin/env python3
"""Quorum — threshold signing broken: audit leaks unlimited static shares.

N=48 shares of a degree-T=24 polynomial (coeff[0]=C0, coeff[1]=C1).
/audit allows T=24 shares per request, but shares never change per round ->
two requests recover the whole polynomial via Lagrange. Then
z = C1 + c*C0 (mod L) where c = challenge derived from public sealed target.

Usage: python3 exp_quorum.py HOST PORT
"""
import json, re, sys, urllib.request

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\s]{8,64}\}")
L = 2 ** 252 + 27742317777372353535851937790883648493

def post(host, port, path, payload):
    req = urllib.request.Request(
        f"http://{host}:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "curl/7.88"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())

def get(host, port, path):
    req = urllib.request.Request(f"http://{host}:{port}{path}",
                                 headers={"User-Agent": "curl/7.88"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())

def lagrange_coeffs(points):
    """Return polynomial coefficients [p0..pT] over Z_L from points [(x, y)...]."""
    # Build coefficient vector via Lagrange: p(x) = sum y_i * prod_{j!=i} (x - x_j)/(x_i - x_j)
    n = len(points)
    coeffs = [0] * n
    for i, (xi, yi) in enumerate(points):
        # poly = prod (x - xj) / (xi - xj), computed as coefficient list
        num = [1]
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            # multiply num by (x - xj)
            new = [0] * (len(num) + 1)
            for k, c in enumerate(num):
                new[k] = (new[k] - xj * c) % L
                new[k + 1] = (new[k + 1] + c) % L
            num = new
            den = den * (xi - xj) % L
        w = yi * pow(den, L - 2, L) % L
        for k, c in enumerate(num):
            coeffs[k] = (coeffs[k] + w * c) % L
    return coeffs

def exploit(host, port, flag_id=None):
    params = get(host, port, "/params")
    N, T = params["n"], params["t"]
    X = [int(x) for x in params["x"]]
    K, M = int(params["bind"]["K"]), int(params["bind"]["M"])
    C_SEALED = int(params["target"])

    shares = {}
    idx = list(range(N))
    for chunk in (idx[:T], idx[T:2 * T]):
        r = post(host, port, "/audit", {"indices": chunk})
        for k, v in r["shares"].items():
            shares[int(k)] = int(v) % L

    pts = [(X[i], shares[i]) for i in sorted(shares)][: T + 1]
    coeffs = lagrange_coeffs(pts)
    C0, C1 = coeffs[0], coeffs[1]

    # sanity: PK should equal C0*B (we can't easily check w/o ed25519 mult; trust it)
    c = (pow(K, L - 2, L) * ((C_SEALED - M) % L) + T) % L
    z = (C1 + c * C0) % L
    r = post(host, port, "/sign", {"z": str(z)})
    if r.get("ok"):
        return FLAG_RE.findall(r.get("record", ""))
    print("[!] sign rejected", r, file=sys.stderr)
    return []

if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    for f in exploit(host, port):
        print(f)
