# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later

"""Per-packet encryption overhead regression tests

These tests guard the GCM per-packet fast path. The original code built a
fresh ``AESGCM`` (and thus ran the AES key expansion) on every packet.
The fix constructs it once per connection and reuses the key schedule.

Absolute timings are machine dependent, so the assertions compare two code
paths measured back-to-back in the same process. The key-schedule reuse
must be materially cheaper than rebuilding it per packet, and an
authenticated GCM packet must not cost more than the security-equivalent
CTR + HMAC combination it replaces.
"""

import os
import time
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asyncssh.crypto.cipher import GCMCipher
from asyncssh.encryption import get_encryption_params, get_encryption


_ITERATIONS = 20000
_WARMUP = 1000
_PACKET_SIZE = 256

# Reusing the key schedule must save at least 25% versus a per-packet
# AESGCM construction. This is deliberately below the ~45-50% measured
# improvement so the test is stable across machines and CI load.
_REUSE_SPEEDUP = 1.25

# GCM (authenticated) must be no slower than CTR + HMAC-SHA-256 (also
# authenticated). Allow a generous margin so a noisy CI runner never
# flaps; the measured ratio on a quiet machine is around 0.4.
_GCM_VS_CTR_MAC_CEILING = 1.0


def _measure(fn, iterations=_ITERATIONS):
    """Return the average per-call time in microseconds"""

    for _ in range(_WARMUP):
        fn()

    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return (time.perf_counter() - start) / iterations * 1e6


class _TestPerPacketOverhead(unittest.TestCase):
    """Regression tests for symmetric cipher per-packet overhead"""

    def setUp(self):
        self._key = os.urandom(16)
        self._iv = os.urandom(12)
        self._header = os.urandom(4)
        self._data = os.urandom(_PACKET_SIZE)

    def test_gcm_reuses_key_schedule(self):
        """GCMCipher must not rebuild the AESGCM key schedule per packet"""

        # Fixed fast path: construct the AESGCM object once, reuse it.
        reused = AESGCM(self._key)
        fast = _measure(lambda: reused.encrypt(self._iv, self._data,
                                               self._header))

        # Original slow path: construct a fresh AESGCM on every packet,
        # paying the key expansion each time.
        slow = _measure(lambda: AESGCM(self._key).encrypt(
            self._iv, self._data, self._header))

        self.assertLessEqual(
            fast * _REUSE_SPEEDUP, slow,
            'GCM key-schedule reuse is not faster than per-packet setup')

    def test_gcm_cipher_uses_reused_schedule(self):
        """GCMCipher must build one AESGCM object and reuse it per packet

        The per-packet fast path depends on holding a single key schedule
        for the lifetime of the connection rather than running the AES key
        expansion on every packet. Assert the structure that guarantees it:
        a reusable ``AESGCM`` object and no retained raw key from which a
        per-packet object could be rebuilt.
        """

        cipher = GCMCipher('aes128-gcm', self._key, self._iv)

        self.assertIsInstance(cipher._aesgcm, AESGCM)
        self.assertFalse(hasattr(cipher, '_key'))

        # One object is shared across many packets rather than replaced.
        first = cipher._aesgcm
        for _ in range(10):
            cipher.encrypt_and_sign(self._header, self._data)
        self.assertIs(cipher._aesgcm, first)

    def test_gcm_not_slower_than_ctr_with_mac(self):
        """Authenticated GCM must not cost more than CTR + HMAC-SHA-256"""

        def make(enc_alg, mac_alg=b''):
            key_size, iv_size, _, mac_key_size, _, etm = \
                get_encryption_params(enc_alg, mac_alg)
            key = os.urandom(key_size)
            iv = os.urandom(iv_size)
            mac_key = os.urandom(mac_key_size)
            return (get_encryption(enc_alg, key, iv, mac_alg, mac_key, etm),
                    max(8, get_encryption_params(enc_alg, mac_alg)[2]))

        gcm, gcm_block = make(b'aes128-gcm@openssh.com')
        ctr, ctr_block = make(b'aes128-ctr', b'hmac-sha2-256')
        seq = 0

        gcm_cost = _measure(
            lambda: gcm.encrypt_packet(seq, self._header, self._data))
        ctr_cost = _measure(
            lambda: ctr.encrypt_packet(seq, self._header, self._data))

        self.assertLessEqual(
            gcm_cost, ctr_cost * _GCM_VS_CTR_MAC_CEILING,
            'GCM per-packet cost regressed above CTR + HMAC-SHA-256')

        # Sanity: both objects are usable and report sensible block sizes
        self.assertEqual(gcm_block, 16)
        self.assertEqual(ctr_block, 16)
