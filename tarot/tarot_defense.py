#!/usr/bin/env python3
"""DEFENSE PATCH — tarot-club (vulnbox kita: 10.13.37.8, SSH port 22022).

JANGAN DIJALANKAN otomatis — review dulu, lalu jalankan manual per baris.

Patch SLA-safe (input/validasi saja, output normal tidak diubah):
  P1. resolvers.js — GraphQL IDOR: User.privateGroups wajib caller == parent.id
  P2. ops-gateway/index.js — ACL smoke: isBlockedPath dicek SETIAP request
  P3. prefs.js — deepMerge: blok __proto__/constructor/prototype + whitelist key
  P4. reportGenerator.js — pdfEngine tidak boleh di-set user (kunci nilai)
  P5. linkPreview.js — SSRF: blok URL internal/localhost/metadata
  P6. (opsional, lebih berisiko) saml.js — tolak assertion dengan role=admin
      yang tidak datang dari IdP login (sudah terjadi via /api/saml/idp/login
      yang menolak admin; XSW tetap mungkin — patch minimal: bandingkan NameID
      assertion dengan username yang diminta)

Cara pakai (manual):
  ssh -p 22022 ctfuser@10.13.37.8
  # backup dulu:
  cp -a /app/backend/src /app/backend/src.bak-$(date +%s)
  cp -a /app/ops-gateway  /app/ops-gateway.bak-$(date +%s)
  # terapkan patch (python3 patch file ini via stdin atau scp dulu):
  python3 tarot_defense.py --apply
  # lalu RESTART dari panel web UI (bukan docker), verifikasi monitor.py UP.
"""
import re, sys, shutil, time

BACKEND = "/app/backend/src/resolvers.js"
OPS = "/app/ops-gateway/index.js"
PREFS = "/app/backend/src/prefs.js"
REPORT = "/app/backend/src/reportGenerator.js"
LINK = "/app/backend/src/linkPreview.js"
SAML = "/app/backend/src/saml.js"

def patch_private_groups(src):
    # before:
    #   User: { privateGroups: async (parent) => { SELECT ... WHERE gm.user_id = $1(parent.id) }
    # after: require context.user.id === parent.id
    old = """        privateGroups: async (parent) => {
            const { rows } = await pool.query("""
    new = """        privateGroups: async (parent, _args, context) => {
            if (!context.user || context.user.id !== parent.id) {
                throw new Error("FORBIDDEN: bukan pemilik ruang ini");
            }
            const { rows } = await pool.query("""
    assert old in src, "privateGroups pattern not found"
    return src.replace(old, new, 1)

def patch_ops_gateway(src):
    # blocked check harus dijalankan untuk SETIAP request, bukan hanya request pertama
    old = """            if (!aclChecked) {
                aclChecked = true;
                if (isBlockedPath(parsed.requestLine)) {"""
    new = """            {
                if (isBlockedPath(parsed.requestLine)) {"""
    assert old in src, "ops-gateway pattern not found"
    return src.replace(old, new, 1)

def patch_prefs(src):
    # deepMerge: tolak key berbahaya + whitelist key runtimeConfig
    old = """function deepMerge(target, source) {
    for (const key of Object.keys(source)) {"""
    new = """const ALLOWED_PREF_KEYS = new Set(["theme", "locale"]);
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
            throw new Error("prefs key tidak diizinkan");
        }
        if (!ALLOWED_PREF_KEYS.has(key)) {
            continue;
        }"""
    assert old in src, "prefs pattern not found"
    return src.replace(old, new, 1)

def patch_report(src):
    # pdfEngine tidak lagi dibaca dari runtimeConfig (nilai statis aman)
    old = 'const engine = runtimeConfig.pdfEngine || "wkhtmltopdf";'
    new = 'const engine = "wkhtmltopdf";'
    assert old in src, "report pattern not found"
    return src.replace(old, new, 1)

def patch_link_preview(src):
    # blok target internal: localhost/private IP/metadata/loopback
    old = """    let targetPath = "";
    try {
        targetPath = new URL(targetUrl).pathname;
    } catch (e) {
        targetPath = "";
    }
    if (/^\\/internal\\//i.test(targetPath)) {
        throw new Error("preview target ditolak");
    }"""
    new = """    let u;
    try {
        u = new URL(targetUrl);
    } catch (e) {
        throw new Error("preview target ditolak");
    }
    if (!/^https?:$/.test(u.protocol)) throw new Error("preview target ditolak");
    const host = u.hostname;
    if (/^(localhost|127\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|169\\.254\\.|
            0\\.0\\.0\\.0|\\[::1\\]|metadata)/i.test(host)) {
        throw new Error("preview target ditolak");
    }"""
    assert old in src, "linkPreview pattern not found"
    return src.replace(old, new, 1)

def patch_saml(src):
    # XSW: verification memilih assertions[0] — pastikan assertion yang diverifikasi
    # adalah yang bertanda tangan: tolak jika ada >1 assertion.
    old = """    const assertions = xpath.select("//*[local-name(.)='Assertion']", doc);
    if (!assertions.length) throw new Error("tidak ada assertion");
    const a = assertions[0];"""
    new = """    const assertions = xpath.select("//*[local-name(.)='Assertion']", doc);
    if (!assertions.length) throw new Error("tidak ada assertion");
    if (assertions.length > 1) throw new Error("assertion ganda ditolak");
    const a = assertions[0];"""
    assert old in src, "saml pattern not found"
    return src.replace(old, new, 1)

PATCHES = [
    (BACKEND, patch_private_groups),
    (OPS, patch_ops_gateway),
    (PREFS, patch_prefs),
    (REPORT, patch_report),
    (LINK, patch_link_preview),
    (SAML, patch_saml),
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
    print("[*] Selesai. RESTART service dari panel web UI, lalu cek monitor.py UP.")
    print("[*] Verifikasi manual: /graphql user(id:2) harus FORBIDDEN, /leaderboard")

if __name__ == "__main__":
    main()
