#!/usr/bin/env python3
"""streams.json -> feed.bin (deflate -> AES-256-GCM -> Ed25519 signature).

Env: FEED_AES_KEY, FEED_SIGNING_KEY (base64, 32 bytes each), FEED_KEY_ID (int 0-255)
Usage: encrypt_feed.py <input streams.json> <output feed.bin>
"""
import base64
import json
import os
import sys
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"LTF1"


def b64_key(name: str) -> bytes:
    key = base64.b64decode(os.environ[name])
    if len(key) != 32:
        sys.exit(f"{name} must decode to 32 bytes")
    return key


def main(src: str, dst: str) -> None:
    raw = open(src, "rb").read()

    # Refuse to publish a feed the apps would reject anyway.
    feed = json.loads(raw)
    if not feed.get("streams"):
        sys.exit("streams.json has no streams - not publishing")

    key_id = int(os.environ["FEED_KEY_ID"])
    header = MAGIC + bytes([key_id])

    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw DEFLATE for iOS NSData .zlib
    compressed = deflater.compress(raw) + deflater.flush()

    nonce = os.urandom(12)
    sealed = AESGCM(b64_key("FEED_AES_KEY")).encrypt(nonce, compressed, header)

    signed = header + nonce + sealed
    signature = Ed25519PrivateKey.from_private_bytes(b64_key("FEED_SIGNING_KEY")).sign(signed)

    with open(dst, "wb") as out:
        out.write(signed + signature)
    print(f"wrote {dst}: {len(feed['streams'])} streams, {len(raw)} -> {len(signed) + 64} bytes")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
