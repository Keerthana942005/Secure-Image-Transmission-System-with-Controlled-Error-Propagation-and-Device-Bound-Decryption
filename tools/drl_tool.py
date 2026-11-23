#!/usr/bin/env python3
"""CLI utility for Ed25519-signed Device Revocation Lists (DRL).
Allows generation of authority keypairs, creation and signing of DRLs,
and offline verification with rollback protection.
"""

import os
import sys
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.key_manager import sign_drl, verify_and_load_drl, DRLSignatureError, DRLRollbackError

def cmd_gen_keys(args):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    
    os.makedirs(os.path.dirname(os.path.abspath(args.out_priv)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_pub)), exist_ok=True)

    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    with open(args.out_priv, "wb") as f:
        f.write(priv_bytes)
    with open(args.out_pub, "wb") as f:
        f.write(pub_bytes)

    print(f"Generated Ed25519 DRL authority keys:")
    print(f"  Private Key: {args.out_priv}")
    print(f"  Public Key:  {args.out_pub} (Fingerprint: {pub_bytes.hex()[:16]}...)")

def cmd_create_drl(args):
    with open(args.priv_key, "rb") as f:
        raw_priv = f.read()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)

    entries = [e.strip() for e in args.entries.split(",") if e.strip()] if args.entries else []
    drl_doc = sign_drl(priv, version=args.version, entries=entries)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(drl_doc, f, indent=2)

    print(f"Created and signed DRL version {args.version} ({len(entries)} entries):")
    print(f"  Output path: {args.out}")
    print(f"  Signature:   {drl_doc['signature'][:32]}...")

def cmd_verify_drl(args):
    with open(args.pub_key, "rb") as f:
        raw_pub = f.read()
    pub = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)

    try:
        drl = verify_and_load_drl(args.drl, pub)
        print(f"[SUCCESS] DRL verified:")
        print(f"  Version:   {drl['version']}")
        print(f"  Entries:   {len(drl['entries'])}")
        print(f"  Issued At: {drl['issued_at']}")
    except (DRLSignatureError, DRLRollbackError) as e:
        print(f"[FAILED] DRL verification error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="DRL Tool: Manage Ed25519-Signed Device Revocation Lists")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # gen-keys
    p_gen = subparsers.add_parser("gen-keys", help="Generate Ed25519 keypair for DRL signing")
    p_gen.add_argument("--out-priv", required=True, help="Path to write private key")
    p_gen.add_argument("--out-pub", required=True, help="Path to write public key")
    p_gen.set_defaults(func=cmd_gen_keys)

    # create-drl
    p_create = subparsers.add_parser("create-drl", help="Create and sign a DRL document")
    p_create.add_argument("--priv-key", required=True, help="Path to Ed25519 private key")
    p_create.add_argument("--version", type=int, required=True, help="Monotonic DRL version number")
    p_create.add_argument("--entries", default="", help="Comma-separated list of hex fingerprints")
    p_create.add_argument("--out", required=True, help="Output path for JSON DRL document")
    p_create.set_defaults(func=cmd_create_drl)

    # verify-drl
    p_verify = subparsers.add_parser("verify-drl", help="Verify signature and integrity of a DRL document")
    p_verify.add_argument("--pub-key", required=True, help="Path to trusted Ed25519 public key")
    p_verify.add_argument("--drl", required=True, help="Path to JSON DRL document")
    p_verify.set_defaults(func=cmd_verify_drl)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

