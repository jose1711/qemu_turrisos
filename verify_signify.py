#!/usr/bin/env python3
# verify signify/usign signature, used by fetch.sh when
# signify itself is not installed
#
# usage: verify_signify.py PUBKEY SIGFILE FILE

import base64
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def read_blob(path):
    # first line is an untrusted comment, second one base64 encoded data
    with open(path) as f:
        blob = base64.b64decode(f.read().splitlines()[1])
    if blob[:2] != b"Ed":
        sys.exit("{}: unsupported algorithm".format(path))
    return blob


def main(pubkey_path, sig_path, path):
    pubkey = read_blob(pubkey_path)
    sig = read_blob(sig_path)
    if pubkey[2:10] != sig[2:10]:
        sys.exit("{}: signed by a different key ({})".format(sig_path, sig[2:10].hex()))
    with open(path, "rb") as f:
        data = f.read()
    try:
        Ed25519PublicKey.from_public_bytes(pubkey[10:42]).verify(sig[10:74], data)
    except InvalidSignature:
        sys.exit("{}: signature verification failed".format(path))
    print("Signature Verified")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: {} PUBKEY SIGFILE FILE".format(sys.argv[0]))
    main(*sys.argv[1:])
