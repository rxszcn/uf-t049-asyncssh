"""Per-packet encryption overhead benchmark (pre/post change comparison).

Measures the cost of encrypting and decrypting SSH-sized packets through
the asyncssh Encryption layer for the default AEAD/streaming algorithms.
Run with: python -I bench_per_packet.py
"""

import os
import time

from asyncssh.encryption import get_encryption_params, get_encryption

PACKET_SIZES = (64, 256, 1024, 4096)
ITERATIONS = 50_000

ALGS = [
    b'chacha20-poly1305@openssh.com',
    b'aes256-gcm@openssh.com',
    b'aes128-gcm@openssh.com',
    b'aes256-ctr',
    b'aes128-ctr',
]


def make(enc_alg):
    key_size, iv_size, _, mac_key_size, _, etm = get_encryption_params(enc_alg)
    key = os.urandom(key_size)
    iv = os.urandom(iv_size)
    mac_key = os.urandom(mac_key_size)
    enc = get_encryption(enc_alg, key, iv, b'', mac_key, etm)
    dec = get_encryption(enc_alg, key, iv, b'', mac_key, etm)
    block_size = max(8, get_encryption_params(enc_alg)[2])
    return enc, dec, block_size


def bench(enc_alg, size, iterations=ITERATIONS):
    enc, dec, block_size = make(enc_alg)
    payload = os.urandom(size)
    hdr = os.urandom(4)
    seq = 0

    # warmup
    for _ in range(2000):
        encdata, mac = enc.encrypt_packet(seq, hdr, payload)
        first, rest = encdata[:block_size], encdata[block_size:]
        _, dechdr = dec.decrypt_header(seq, first, 4)
        dec.decrypt_packet(seq, first, rest, 4, mac)

    start = time.perf_counter()
    for _ in range(iterations):
        encdata, mac = enc.encrypt_packet(seq, hdr, payload)
        first, rest = encdata[:block_size], encdata[block_size:]
        dec.decrypt_header(seq, first, 4)
        dec.decrypt_packet(seq, first, rest, 4, mac)
    elapsed = time.perf_counter() - start

    return elapsed / iterations * 1e6  # microseconds per packet (full round trip)


def main():
    print(f"{'algorithm':<32}{'size':>6}{'us/pkt (enc+dec)':>18}")
    baseline = {}
    for alg in ALGS:
        for size in PACKET_SIZES:
            try:
                us = bench(alg, size)
            except Exception as exc:  # pragma: no cover
                print(f"{alg.decode():<32}{size:>6}  ERROR: {exc}")
                continue
            print(f"{alg.decode():<32}{size:>6}{us:>18.3f}")
            baseline.setdefault(alg, {})[size] = us
        print()

    # relative overhead of GCM vs the lightweight CTR alternative
    ref128 = baseline.get(b'aes128-ctr', {})
    for gcm in (b'aes256-gcm@openssh.com', b'aes128-gcm@openssh.com'):
        if gcm in baseline and ref128:
            print(f"{gcm.decode()} vs aes128-ctr ratio:")
            for size in PACKET_SIZES:
                ratio = baseline[gcm][size] / ref128[size]
                print(f"  size={size:>5}: {ratio:.2f}x")
            print()


if __name__ == '__main__':
    main()
