# Copyright (C) 2015-2026 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from virgil_crypto_lib._libs import *
from ctypes import *
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_shamir_t(Structure):
    pass


class VscfShamir(object):
    """Threshold secret sharing based on Shamir's scheme over GF(256).

Splits an arbitrary-length secret into 'share count' shares so that any
'threshold' of them reconstruct the secret, while fewer reveal nothing.

Construction (split-key-encrypt-data): a random 32-byte data key is
generated, the secret is encrypted with it using AES-256-GCM, and only the
data key is Shamir-split. Each share is self-contained (it embeds the
encrypted secret). Recovery combines the shares to rebuild the data key,
verifies a commitment to it, and authenticates the decryption with the GCM
tag - so wrong, tampered, insufficient, or cross-split shares fail cleanly."""


    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_shamir_new(self):
        vscf_shamir_new = self._lib.vscf_shamir_new
        vscf_shamir_new.argtypes = []
        vscf_shamir_new.restype = POINTER(vscf_shamir_t)
        return vscf_shamir_new()

    def vscf_shamir_delete(self, ctx):
        vscf_shamir_delete = self._lib.vscf_shamir_delete
        vscf_shamir_delete.argtypes = [POINTER(vscf_shamir_t)]
        vscf_shamir_delete.restype = None
        return vscf_shamir_delete(ctx)

    def vscf_shamir_use_random(self, ctx, random):
        vscf_shamir_use_random = self._lib.vscf_shamir_use_random
        vscf_shamir_use_random.argtypes = [POINTER(vscf_shamir_t), POINTER(vscf_impl_t)]
        vscf_shamir_use_random.restype = None
        return vscf_shamir_use_random(ctx, random)

    def vscf_shamir_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies:
a CTR DRBG random number generator."""
        vscf_shamir_setup_defaults = self._lib.vscf_shamir_setup_defaults
        vscf_shamir_setup_defaults.argtypes = [POINTER(vscf_shamir_t)]
        vscf_shamir_setup_defaults.restype = c_int
        return vscf_shamir_setup_defaults(ctx)

    def vscf_shamir_share_len(self, secret_len):
        """Calculate the length in bytes of a single share produced for a secret
of the given length."""
        vscf_shamir_share_len = self._lib.vscf_shamir_share_len
        vscf_shamir_share_len.argtypes = [c_size_t]
        vscf_shamir_share_len.restype = c_size_t
        return vscf_shamir_share_len(secret_len)

    def vscf_shamir_shares_len(self, secret_len, share_count):
        """Calculate the length in bytes of the buffer needed to hold all shares
produced by 'split' for a secret of the given length and the given
number of shares."""
        vscf_shamir_shares_len = self._lib.vscf_shamir_shares_len
        vscf_shamir_shares_len.argtypes = [c_size_t, c_size_t]
        vscf_shamir_shares_len.restype = c_size_t
        return vscf_shamir_shares_len(secret_len, share_count)

    def vscf_shamir_recovered_secret_len(self, shares_len, share_count):
        """Calculate an upper bound on the length in bytes of the recovered secret
for the given total shares length and number of provided shares.
The exact length is set on the output buffer by 'combine'."""
        vscf_shamir_recovered_secret_len = self._lib.vscf_shamir_recovered_secret_len
        vscf_shamir_recovered_secret_len.argtypes = [c_size_t, c_size_t]
        vscf_shamir_recovered_secret_len.restype = c_size_t
        return vscf_shamir_recovered_secret_len(shares_len, share_count)

    def vscf_shamir_split(self, ctx, secret, threshold, share_count, out):
        """Split the given secret into 'share count' shares with reconstruction
'threshold'. Requires a configured random number generator (see
'setup defaults' / 'use random').

Constraints: 1 <= threshold <= share count <= 255.

The produced shares are written consecutively to 'out', each of length
'share len(secret.len)'."""
        vscf_shamir_split = self._lib.vscf_shamir_split
        vscf_shamir_split.argtypes = [POINTER(vscf_shamir_t), vsc_data_t, c_size_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_shamir_split.restype = c_int
        return vscf_shamir_split(ctx, secret, threshold, share_count, out)

    def vscf_shamir_combine(self, ctx, shares, share_count, secret):
        """Reconstruct the secret from 'share count' shares concatenated in
'shares'. 'share count' must be at least the threshold used at split
time.

Returns 'success' and writes the secret to 'secret' on success.
Returns 'error shamir recovery failed' if the shares are wrong,
tampered, insufficient, or do not belong to the same split."""
        vscf_shamir_combine = self._lib.vscf_shamir_combine
        vscf_shamir_combine.argtypes = [POINTER(vscf_shamir_t), vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_shamir_combine.restype = c_int
        return vscf_shamir_combine(ctx, shares, share_count, secret)

    def vscf_shamir_shallow_copy(self, ctx):
        vscf_shamir_shallow_copy = self._lib.vscf_shamir_shallow_copy
        vscf_shamir_shallow_copy.argtypes = [POINTER(vscf_shamir_t)]
        vscf_shamir_shallow_copy.restype = POINTER(vscf_shamir_t)
        return vscf_shamir_shallow_copy(ctx)
