# Per-packet encryption overhead benchmarks

These micro-benchmarks measure the cost of encrypting and decrypting
SSH-sized packets through the AsyncSSH `Encryption` layer. They back the
GCM per-packet fast path change in `asyncssh/crypto/cipher.py` and the
default algorithm reordering in `asyncssh/encryption.py`.

Run either script directly from the repository root with an isolated
interpreter (the editable install makes `asyncssh` importable):

```
python -I benchmarks/bench_per_packet.py
python -I benchmarks/bench_aead_vs_ctr_mac.py
```

## What each script shows

- `bench_per_packet.py` — per-packet round-trip (encrypt + decrypt) cost
  for each default algorithm across several packet sizes, plus the ratio
  of each GCM cipher against bare `aes128-ctr`. Bare CTR provides no
  authentication, so treat this as a primitive-level comparison only.

- `bench_aead_vs_ctr_mac.py` — the security-equivalent comparison. GCM is
  an AEAD, so its real lightweight alternative is a CTR cipher paired
  with a MAC. This shows optimized GCM is faster than
  `aes128-ctr + hmac-sha2-256` at every packet size.

## Why GCM got faster

The original `GCMCipher` constructed a fresh `AESGCM` object on every
packet, rerunning the AES key expansion each time. The object only wraps
the key, which is invariant for a connection, so it is now built once in
`GCMCipher.__init__` and reused. The wire format (RFC 5647 fixed-IV +
invocation-counter construction, header authenticated as AAD) is
unchanged; `tests/test_encryption.py` cross-checks the output against the
independent PyCA `AESGCM` primitive.

Timings are machine dependent and vary between runs; the regression
guard in `tests/test_perf_encryption.py` therefore compares code paths
measured back-to-back rather than asserting absolute numbers.
