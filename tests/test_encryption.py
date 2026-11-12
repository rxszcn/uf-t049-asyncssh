# Copyright (c) 2015-2020 by Ron Frederick <ronf@timeheart.net> and others.
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
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for symmetric key encryption"""

import os
import random
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asyncssh.crypto.cipher import GCMCipher
from asyncssh.encryption import register_encryption_alg, get_encryption_algs
from asyncssh.encryption import get_encryption_params, get_encryption
from asyncssh.mac import get_mac_algs


_GCM_ENC_ALGS = (b'aes128-gcm@openssh.com', b'aes256-gcm@openssh.com')
_GCM_CIPHER_NAMES = {
    b'aes128-gcm@openssh.com': 'aes128-gcm',
    b'aes256-gcm@openssh.com': 'aes256-gcm'
}


class _TestEncryption(unittest.TestCase):
    """Unit tests for encryption module"""

    def check_encryption_alg(self, enc_alg, mac_alg):
        """Check a symmetric encryption algorithm"""

        enc_keysize, enc_ivsize, enc_blocksize, mac_keysize, _, etm = \
            get_encryption_params(enc_alg, mac_alg)

        enc_blocksize = max(8, enc_blocksize)

        enc_key = os.urandom(enc_keysize)
        enc_iv = os.urandom(enc_ivsize)
        mac_key = os.urandom(mac_keysize)

        seq = random.getrandbits(32)

        enc = get_encryption(enc_alg, enc_key, enc_iv, mac_alg, mac_key, etm)
        dec = get_encryption(enc_alg, enc_key, enc_iv, mac_alg, mac_key, etm)

        for i in range(2, 6):
            data = os.urandom(4*etm + i*enc_blocksize)
            hdr, packet = data[:4], data[4:]

            encdata, encmac = enc.encrypt_packet(seq, hdr, packet)

            first, rest = encdata[:enc_blocksize], encdata[enc_blocksize:]

            decfirst, dechdr = dec.decrypt_header(seq, first, 4)

            decdata = dec.decrypt_packet(seq, decfirst, rest, 4, encmac)

            self.assertEqual(dechdr, hdr)
            self.assertEqual(decdata, packet)

            seq = (seq + 1) & 0xffffffff

    def test_encryption_algs(self):
        """Unit test encryption algorithms"""

        for enc_alg in get_encryption_algs():
            for mac_alg in get_mac_algs():
                with self.subTest(enc_alg=enc_alg, mac_alg=mac_alg):
                    self.check_encryption_alg(enc_alg, mac_alg)

    def test_unavailable_cipher(self):
        """Test registering encryption that uses an unavailable cipher"""

        # pylint: disable=no-self-use

        register_encryption_alg('xxx', 'xxx', '', True)

    def test_gcm_wire_format_interop(self):
        """Check GCM packets are byte-compatible with a standard AES-GCM

        RFC 5647 defines the SSH AES-GCM wire format: a 12-byte IV made of
        a 4-byte fixed prefix and an 8-byte big-endian invocation counter,
        with the packet header authenticated as additional data. The output
        of GCMCipher must be identical to that of the independent PyCA
        ``AESGCM`` primitive a standards-compliant peer would use.
        """

        for enc_alg in _GCM_ENC_ALGS:
            with self.subTest(enc_alg=enc_alg):
                key_size, iv_size, _, _, _, _ = \
                    get_encryption_params(enc_alg)

                key = os.urandom(key_size)
                fixed = os.urandom(4)
                iv = fixed + (0).to_bytes(iv_size - 4, 'big')
                cipher_name = _GCM_CIPHER_NAMES[enc_alg]

                ssh_cipher = GCMCipher(cipher_name, key, iv)
                peer = AESGCM(key)

                for seq in range(5):
                    header = os.urandom(4)
                    payload = os.urandom(16 + seq * 37)
                    expected_iv = fixed + seq.to_bytes(8, 'big')

                    # What a standard peer would emit for this packet
                    sealed = peer.encrypt(expected_iv, payload, header)

                    # What AsyncSSH emits
                    wire, tag = ssh_cipher.encrypt_and_sign(header, payload)

                    self.assertEqual(wire, header + sealed[:-16])
                    self.assertEqual(tag, sealed[-16:])

                    # A standard peer must accept AsyncSSH's packet
                    decrypted = AESGCM(key).decrypt(
                        expected_iv, wire[4:] + tag, header)
                    self.assertEqual(decrypted, payload)

    def test_gcm_decrypt_interop_and_tamper(self):
        """Check GCM decrypts standard peer packets and rejects tampering"""

        for enc_alg in _GCM_ENC_ALGS:
            with self.subTest(enc_alg=enc_alg):
                key_size, iv_size, _, _, _, _ = \
                    get_encryption_params(enc_alg)

                key = os.urandom(key_size)
                fixed = os.urandom(4)
                initial_iv = fixed + (0).to_bytes(iv_size - 4, 'big')
                cipher_name = _GCM_CIPHER_NAMES[enc_alg]

                # A fresh cipher starts its invocation counter at zero,
                # matching the independently generated peer packets.
                ssh_cipher = GCMCipher(cipher_name, key, initial_iv)
                peer = AESGCM(key)

                for seq in range(5):
                    header = os.urandom(4)
                    payload = os.urandom(64)
                    expected_iv = fixed + seq.to_bytes(8, 'big')

                    sealed = peer.encrypt(expected_iv, payload, header)
                    ciphertext, tag = sealed[:-16], sealed[-16:]

                    # AsyncSSH decrypts a packet a standard peer produced
                    result = ssh_cipher.verify_and_decrypt(
                        header, ciphertext, tag)
                    self.assertEqual(result, payload)

                    # A flipped bit must be rejected rather than decrypted.
                    # Use a separate cipher so the tampered packet's IV
                    # advance doesn't desync the valid packet sequence.
                    tamper_cipher = GCMCipher(
                        cipher_name, key, expected_iv)
                    tampered = bytearray(ciphertext)
                    tampered[0] ^= 0x01
                    self.assertIsNone(
                        tamper_cipher.verify_and_decrypt(
                            header, bytes(tampered), tag))

                    # And an invalid tag must raise at the primitive layer
                    with self.assertRaises(InvalidTag):
                        AESGCM(key).decrypt(
                            expected_iv, ciphertext + b'\x00' * 16, header)
