#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gm_dump_parser.py - GraveMemory dump parser (auto-detect)

Parses:

  1. GraveMemory plaintext record stream  (gravememory.dmp)          - default
  2. Legacy sealed GraveMemory containers  (RSA/AES)                 - needs
     the collector private key:  --key priv.pem  (requires the
     'cryptography' package)

Auto-detection is based on the first 4 bytes:
  - plaintext stream starts with a LITTLE-ENDIAN u32 (domain byte length,
    always small)
  - sealed container starts with a BIG-ENDIAN u32 (encrypted key size,
    256 for RSA-2048)

Usage:
    python3 gm_dump_parser.py gravememory.dmp
    python3 gm_dump_parser.py gravememory.dmp --json
    python3 gm_dump_parser.py legacy_sealed.dmp --key priv.pem

AUTHORIZED USE ONLY - audit dumps of systems you own or are explicitly
authorized to assess. Dump files contain real password hashes.
"""

import argparse
import struct
import sys
from datetime import datetime, timedelta, timezone

LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"
NT_NOPASS = "31d6cfe0d16ae931b73c59d7e0c089c0"

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft):
    """raw FILETIME -> 'YYYY-MM-DD HH:MM:SS UTC' or None"""
    if ft == 0:
        return None
    try:
        dt = EPOCH + timedelta(microseconds=ft // 10)
        if dt.year < 1601 or dt.year > 9999:
            return None
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


def lm_note(h):
    if h is None:
        return None
    if h == LM_EMPTY:
        return "No Password"
    if h.startswith("aad3b435b51404ee"):
        return "second half set"
    if len(h) == 32 and h.endswith("aad3b435b51404ee"):
        return "first half set"
    return None


def nt_note(h):
    if h is not None and h == NT_NOPASS:
        return "No Password"
    return None


class Reader:
    def __init__(self, data):
        self.d = data
        self.o = 0

    def take(self, n):
        if self.o + n > len(self.d):
            raise EOFError("unexpected end of record stream")
        b = self.d[self.o:self.o + n]
        self.o += n
        return b

    def u8(self):
        return self.take(1)[0]

    def u32le(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64le(self):
        return struct.unpack("<Q", self.take(8))[0]

    def utf16_field(self):
        """[u32 byte_len][len bytes UTF-16LE incl. NUL] -> python str"""
        n = self.u32le()
        raw = self.take(n + 2)
        if raw[-2:] != b"\x00\x00":
            raise ValueError("string field is not NUL-terminated")
        return raw[:-2].decode("utf-16-le", errors="replace")

    @property
    def eof(self):
        return self.o >= len(self.d)


def parse_stream(data):
    """parse plaintext record stream -> (domain, [user dicts])"""
    r = Reader(data)
    domain = r.utf16_field()
    users = []
    while not r.eof:
        u = {}
        u["username"] = r.utf16_field()
        u["fullname"] = r.utf16_field()
        u["admin_comment"] = r.utf16_field()
        u["home_dir"] = r.utf16_field()
        u["rid"] = r.u32le()
        has_nt = r.u8()
        u["nt_hex"] = r.take(16).hex() if has_nt else None
        has_lm = r.u8()
        u["lm_hex"] = r.take(16).hex() if has_lm else None
        ft = r.u64le()
        u["password_last_set"] = filetime_to_iso(ft)
        u["password_last_set_raw"] = ft
        u["flags"] = {
            "locked_out": bool(r.u8()),
            "disabled": bool(r.u8()),
            "never_expires": bool(r.u8()),
            "expired": bool(r.u8()),
        }
        u["nt_present"] = bool(has_nt)
        u["lm_present"] = bool(has_lm)
        u["nt_note"] = nt_note(u["nt_hex"])
        u["lm_note"] = lm_note(u["lm_hex"])
        users.append(u)
    return domain, users


def try_unseal(data, key_path):
    """decrypt a legacy sealed GraveMemory container
    (EVP_Seal RSA-2048 + AES-256-CBC).

    Layout: [u32 BE eklen][eklen bytes RSA-encrypted AES key][16B IV][body]
    Returns the plaintext record-stream bytes.
    """
    try:
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        sys.exit("sealed dump needs the 'cryptography' package:  pip install cryptography")

    with open(key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)

    eklen = struct.unpack(">I", data[:4])[0]
    if not (0 < eklen <= 512):
        raise ValueError("implausible encrypted-key size %d" % eklen)
    ek = data[4:4 + eklen]
    iv = data[4 + eklen:4 + eklen + 16]
    body = data[4 + eklen + 16:]

    aeskey = priv.decrypt(ek, padding.PKCS1v15())
    dec = Cipher(algorithms.AES(aeskey), modes.CBC(iv)).decryptor()
    plain = dec.update(body) + dec.finalize()
    return plain.rstrip(b"\x00")


def looks_sealed(data):
    if len(data) < 4:
        return False
    be = struct.unpack(">I", data[:4])[0]
    le = struct.unpack("<I", data[:4])[0]
    return le >= 0x10000 and 0 < be <= 512


def build_pwdump(users):
    lines = []
    for u in users:
        lines.append("%s:%d:%s:%s:::" % (
            u["username"], u["rid"],
            u["lm_hex"] or LM_EMPTY,
            u["nt_hex"] or NT_NOPASS))
    return "\n".join(lines)


def print_table(domain, users):
    print("=" * 62)
    print("GraveMemory dump parser")
    print("=" * 62)
    print("Domain            : %s" % domain)
    print("Users             : %d" % len(users))
    print("-" * 62)
    print("  %-22s %-7s %-4s %-33s %-33s" % ("USERNAME", "RID", "FLG", "NT", "LM"))
    print("-" * 62)
    for u in users:
        f = u["flags"]
        flg = ("L" if f["locked_out"] else ".") + \
              ("D" if f["disabled"] else ".") + \
              ("E" if f["never_expires"] else ".") + \
              ("X" if f["expired"] else ".")
        print("  %-22s %-7d %-4s %-33s %-33s" % (
            u["username"][:22], u["rid"], flg,
            u["nt_hex"] or "-", u["lm_hex"] or "-"))
    print("-" * 62)
    print("FLAGS: L=locked_out D=disabled E=never_expires X=expired")
    print("pwdump format (user:RID:LM:NT:::):")
    print(build_pwdump(users))


def main():
    ap = argparse.ArgumentParser(description="GraveMemory dump parser")
    ap.add_argument("dumpfile")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of table")
    ap.add_argument("--plain", action="store_true", help="force plaintext parsing")
    ap.add_argument("--key", help="PEM private key for legacy sealed GraveMemory dumps")
    args = ap.parse_args()

    with open(args.dumpfile, "rb") as f:
        data = f.read()

    sealed = looks_sealed(data) and not args.plain
    if sealed and not args.key:
        sys.exit("legacy sealed container detected - pass the collector key:  --key priv.pem\n"
                 "(GraveMemory's own gravememory.dmp files are PLAINTEXT and need no key;\n"
                 "use --plain to force plaintext parsing)")
    if sealed:
        data = try_unseal(data, args.key)

    try:
        domain, users = parse_stream(data)
    except (EOFError, ValueError, struct.error) as e:
        sys.exit("parse error: %s" % e)

    if args.json:
        import json
        report = {
            "tool": "gm_dump_parser",
            "source": args.dumpfile,
            "sealed_input": sealed,
            "domain": domain,
            "user_count": len(users),
            "users": users,
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_table(domain, users)


if __name__ == "__main__":
    main()
