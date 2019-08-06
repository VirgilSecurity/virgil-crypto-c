# Copyright (C) 2015-2019 Virgil Security, Inc.
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


class vscf_ecies_t(Structure):
    pass


class VscfEcies(object):
    """Virgil implementation of the ECIES algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_ecies_new(self):
        vscf_ecies_new = self._lib.vscf_ecies_new
        vscf_ecies_new.argtypes = []
        vscf_ecies_new.restype = POINTER(vscf_ecies_t)
        return vscf_ecies_new()

    def vscf_ecies_delete(self, ctx):
        vscf_ecies_delete = self._lib.vscf_ecies_delete
        vscf_ecies_delete.argtypes = [POINTER(vscf_ecies_t)]
        vscf_ecies_delete.restype = None
        return vscf_ecies_delete(ctx)

    def vscf_ecies_use_random(self, ctx, random):
        vscf_ecies_use_random = self._lib.vscf_ecies_use_random
        vscf_ecies_use_random.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_use_random.restype = None
        return vscf_ecies_use_random(ctx, random)

    def vscf_ecies_use_cipher(self, ctx, cipher):
        vscf_ecies_use_cipher = self._lib.vscf_ecies_use_cipher
        vscf_ecies_use_cipher.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_use_cipher.restype = None
        return vscf_ecies_use_cipher(ctx, cipher)

    def vscf_ecies_use_mac(self, ctx, mac):
        vscf_ecies_use_mac = self._lib.vscf_ecies_use_mac
        vscf_ecies_use_mac.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_use_mac.restype = None
        return vscf_ecies_use_mac(ctx, mac)

    def vscf_ecies_use_kdf(self, ctx, kdf):
        vscf_ecies_use_kdf = self._lib.vscf_ecies_use_kdf
        vscf_ecies_use_kdf.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_use_kdf.restype = None
        return vscf_ecies_use_kdf(ctx, kdf)

    def vscf_ecies_use_ephemeral_key(self, ctx, ephemeral_key):
        """Set ephemeral key that used for data encryption.
        Public and ephemeral keys should belong to the same curve.
        This dependency is optional."""
        vscf_ecies_use_ephemeral_key = self._lib.vscf_ecies_use_ephemeral_key
        vscf_ecies_use_ephemeral_key.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_use_ephemeral_key.restype = None
        return vscf_ecies_use_ephemeral_key(ctx, ephemeral_key)

    def vscf_ecies_set_key_alg(self, ctx, key_alg):
        """Set weak reference to the key algorithm.
        Key algorithm MUST support shared key computation as well."""
        vscf_ecies_set_key_alg = self._lib.vscf_ecies_set_key_alg
        vscf_ecies_set_key_alg.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t)]
        vscf_ecies_set_key_alg.restype = None
        return vscf_ecies_set_key_alg(ctx, key_alg)

    def vscf_ecies_release_key_alg(self, ctx):
        """Release weak reference to the key algorithm."""
        vscf_ecies_release_key_alg = self._lib.vscf_ecies_release_key_alg
        vscf_ecies_release_key_alg.argtypes = [POINTER(vscf_ecies_t)]
        vscf_ecies_release_key_alg.restype = None
        return vscf_ecies_release_key_alg(ctx)

    def vscf_ecies_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_ecies_setup_defaults = self._lib.vscf_ecies_setup_defaults
        vscf_ecies_setup_defaults.argtypes = [POINTER(vscf_ecies_t)]
        vscf_ecies_setup_defaults.restype = c_int
        return vscf_ecies_setup_defaults(ctx)

    def vscf_ecies_setup_defaults_no_random(self, ctx):
        """Setup predefined values to the uninitialized class dependencies
        except random."""
        vscf_ecies_setup_defaults_no_random = self._lib.vscf_ecies_setup_defaults_no_random
        vscf_ecies_setup_defaults_no_random.argtypes = [POINTER(vscf_ecies_t)]
        vscf_ecies_setup_defaults_no_random.restype = None
        return vscf_ecies_setup_defaults_no_random(ctx)

    def vscf_ecies_encrypted_len(self, ctx, public_key, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        vscf_ecies_encrypted_len = self._lib.vscf_ecies_encrypted_len
        vscf_ecies_encrypted_len.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t), c_size_t]
        vscf_ecies_encrypted_len.restype = c_size_t
        return vscf_ecies_encrypted_len(ctx, public_key, data_len)

    def vscf_ecies_encrypt(self, ctx, public_key, data, out):
        """Encrypt data with a given public key."""
        vscf_ecies_encrypt = self._lib.vscf_ecies_encrypt
        vscf_ecies_encrypt.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_ecies_encrypt.restype = c_int
        return vscf_ecies_encrypt(ctx, public_key, data, out)

    def vscf_ecies_decrypted_len(self, ctx, private_key, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_ecies_decrypted_len = self._lib.vscf_ecies_decrypted_len
        vscf_ecies_decrypted_len.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t), c_size_t]
        vscf_ecies_decrypted_len.restype = c_size_t
        return vscf_ecies_decrypted_len(ctx, private_key, data_len)

    def vscf_ecies_decrypt(self, ctx, private_key, data, out):
        """Decrypt given data."""
        vscf_ecies_decrypt = self._lib.vscf_ecies_decrypt
        vscf_ecies_decrypt.argtypes = [POINTER(vscf_ecies_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_ecies_decrypt.restype = c_int
        return vscf_ecies_decrypt(ctx, private_key, data, out)

    def vscf_ecies_shallow_copy(self, ctx):
        vscf_ecies_shallow_copy = self._lib.vscf_ecies_shallow_copy
        vscf_ecies_shallow_copy.argtypes = [POINTER(vscf_ecies_t)]
        vscf_ecies_shallow_copy.restype = POINTER(vscf_ecies_t)
        return vscf_ecies_shallow_copy(ctx)
