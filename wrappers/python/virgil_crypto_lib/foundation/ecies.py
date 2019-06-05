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
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from .encrypt import Encrypt
from .decrypt import Decrypt


class Ecies(Encrypt, Decrypt):
    """Virgil implementation of the ECIES algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_ecies = VscfEcies()
        self._c_impl = None
        self._ctx = None
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

    def set_encryption_key(self, encryption_key):
        """Set public key that is used for data encryption.

        If ephemeral key is not defined, then Public Key, must be conformed
        to the interface "generate ephemeral key".

        In turn, Ephemeral Key must be conformed to the interface
        "compute shared key"."""
        self._lib_vscf_ecies.vscf_ecies_use_encryption_key(self.ctx, encryption_key.c_impl)

    def set_decryption_key(self, decryption_key):
        """Set private key that used for data decryption.

        Private Key must be conformed to the interface "compute shared key"."""
        self._lib_vscf_ecies.vscf_ecies_use_decryption_key(self.ctx, decryption_key.c_impl)

    def set_ephemeral_key(self, ephemeral_key):
        """Set private key that used for data decryption.

        Ephemeral Key must be conformed to the interface "compute shared key"."""
        self._lib_vscf_ecies.vscf_ecies_use_ephemeral_key(self.ctx, ephemeral_key.c_impl)

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_ecies.vscf_ecies_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_ecies.vscf_ecies_encrypted_len(self.ctx, data_len)
        return result

    def decrypt(self, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(data_len=len(data)))
        status = self._lib_vscf_ecies.vscf_ecies_decrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_ecies.vscf_ecies_decrypted_len(self.ctx, data_len)
        return result

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_ecies.vscf_ecies_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

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

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_ecies.vscf_ecies_shallow_copy(value)
        self._c_impl = self._lib_vscf_ecies.vscf_ecies_impl(self.ctx)
