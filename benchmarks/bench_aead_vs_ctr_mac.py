"""Apples-to-apples comparison: AEAD (GCM) vs CTR + separate MAC.

GCM provides authenticated encryption, so the fair lightweight
alternative is a CTR cipher paired with a MAC (the SSH EtM/non-EtM
combination), not bare CTR.
"""

import os
import time

from asyncssh.encryption import get_encryption_params, get_encryption
from asyncssh.mac import get_mac_algs

PACKET_SIZES = (64, 256, 1024, 4096)
ITERATIONS = 40000

# (encryption alg, mac alg) pairs
PAIRS = [
    (b'aes128-gcm@openssh.com', b''),
    (b'aes256-gcm@openssh.com', b''),
    (b'aes128-ctr', b'hmac-sha2-256'),
    (b'aes128-ctr', b'hmac-sha2-512'),
    (b'aes128-ctr', b'hmac-sha1'),
    (b'aes256-ctr', b'hmac-sha2-256'),
    (b'chacha20-poly1305@openssh.com', b''),
]


def make(enc_alg, mac_alg):
    key_size, iv_size, _, mac_key_size, _, etm = \
        get_encryption_params(enc_alg, mac_alg)
    key = os.urandom(key_size)
    iv = os.urandom(iv_size)
    mac_key = os.urandom(mac_key_size)
    enc = get_encryption(enc_alg, key, iv, mac_alg, mac_key, etm)
    dec = get_encryption(enc_alg, key, iv, mac_alg, mac_key, etm)
    block_size = max(8, get_encryption_params(enc_alg, mac_alg)[2])
    return enc, dec, block_size


def bench(enc_alg, mac_alg, size, iterations=ITERATIONS):
    enc, dec, block_size = make(enc_alg, mac_alg)
    payload = os.urandom(size)
    hdr = os.urandom(4)
    seq = 0

    for _ in range(2000):
        encdata, mac = enc.encrypt_packet(seq, hdr, payload)
        first, rest = encdata[:block_size], encdata[block_size:]
        dec.decrypt_header(seq, first, 4)
        dec.decrypt_packet(seq, first, rest, 4, mac)

    start = time.perf_counter()
    for _ in range(iterations):
        encdata, mac = enc.encrypt_packet(seq, hdr, payload)
        first, rest = encdata[:block_size], encdata[block_size:]
        dec.decrypt_header(seq, first, 4)
        dec.decrypt_packet(seq, first, rest, 4, mac)
    return (time.perf_counter() - start) / iterations * 1e6


def main():
    available_macs = set(get_mac_algs())
    header = f"{'enc + mac':<40}{'size':>6}{'us/pkt':>10}"
    print(header)
    results = {}
    for enc_alg, mac_alg in PAIRS:
        if mac_alg and mac_alg not in available_macs:
            continue
        label = enc_alg.decode() + (f' + {mac_alg.decode()}' if mac_alg else '')
        results[label] = {}
        for size in PACKET_SIZES:
            us = bench(enc_alg, mac_alg, size)
            results[label][size] = us
            print(f"{label:<40}{size:>6}{us:>10.3f}")
        print()

    ref = results.get('aes128-ctr + hmac-sha2-256')
    gcm = results.get('aes128-gcm@openssh.com')
    if ref and gcm:
        print("aes128-gcm vs aes128-ctr+hmac-sha2-256 (both authenticated):")
        for size in PACKET_SIZES:
            ratio = gcm[size] / ref[size]
            verdict = "faster" if ratio < 1.0 else "slower"
            print(f"  size={size:>5}: {ratio:.2f}x ({verdict})")


if __name__ == '__main__':
    main()
