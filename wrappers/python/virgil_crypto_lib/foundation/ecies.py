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


from ctypes import *
from ._c_bridge import VscfEcies
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class Ecies(object):
    """Virgil implementation of the ECIES algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_ecies = VscfEcies()
        self.ctx = self._lib_vscf_ecies.vscf_ecies_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_ecies.vscf_ecies_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_ecies.vscf_ecies_use_random(self.ctx, random.c_impl)

    def set_cipher(self, cipher):
        self._lib_vscf_ecies.vscf_ecies_use_cipher(self.ctx, cipher.c_impl)

    def set_mac(self, mac):
        self._lib_vscf_ecies.vscf_ecies_use_mac(self.ctx, mac.c_impl)

    def set_kdf(self, kdf):
        self._lib_vscf_ecies.vscf_ecies_use_kdf(self.ctx, kdf.c_impl)

    def set_ephemeral_key(self, ephemeral_key):
        """Set ephemeral key that used for data encryption.
        Public and ephemeral keys should belong to the same curve.
        This dependency is optional."""
        self._lib_vscf_ecies.vscf_ecies_use_ephemeral_key(self.ctx, ephemeral_key.c_impl)

    def set_key_alg(self, key_alg):
        """Set weak reference to the key algorithm.
        Key algorithm MUST support shared key computation as well."""
        self._lib_vscf_ecies.vscf_ecies_set_key_alg(self.ctx, key_alg.c_impl)

    def release_key_alg(self):
        """Release weak reference to the key algorithm."""
        self._lib_vscf_ecies.vscf_ecies_release_key_alg(self.ctx)

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_ecies.vscf_ecies_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def setup_defaults_no_random(self):
        """Setup predefined values to the uninitialized class dependencies
        except random."""
        self._lib_vscf_ecies.vscf_ecies_setup_defaults_no_random(self.ctx)

    def encrypted_len(self, public_key, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_ecies.vscf_ecies_encrypted_len(self.ctx, public_key.c_impl, data_len)
        return result

    def encrypt(self, public_key, data):
        """Encrypt data with a given public key."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(public_key=public_key, data_len=len(data)))
        status = self._lib_vscf_ecies.vscf_ecies_encrypt(self.ctx, public_key.c_impl, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, private_key, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_ecies.vscf_ecies_decrypted_len(self.ctx, private_key.c_impl, data_len)
        return result

    def decrypt(self, private_key, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(private_key=private_key, data_len=len(data)))
        status = self._lib_vscf_ecies.vscf_ecies_decrypt(self.ctx, private_key.c_impl, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecies = VscfEcies()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecies = VscfEcies()
        inst.ctx = inst._lib_vscf_ecies.vscf_ecies_shallow_copy(c_ctx)
        return inst
