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
from ._c_bridge import VscfCurve25519PublicKey
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge._vscf_error import vscf_error_t
from .alg import Alg
from .key import Key
from .encrypt import Encrypt
from .public_key import PublicKey
from .generate_ephemeral_key import GenerateEphemeralKey


class Curve25519PublicKey(Alg, Key, Encrypt, PublicKey, GenerateEphemeralKey):
    """This is implementation of CURVE25519 public key"""

    # Defines whether a public key can be imported or not.
    CAN_IMPORT_PUBLIC_KEY = True
    # Define whether a public key can be exported or not.
    CAN_EXPORT_PUBLIC_KEY = True

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_curve25519_public_key = VscfCurve25519PublicKey()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_use_random(self.ctx, random.c_impl)

    def set_ecies(self, ecies):
        self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_use_ecies(self.ctx, ecies.ctx)

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def key_len(self):
        """Length of the key in bytes."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_key_len(self.ctx)
        return result

    def key_bitlen(self):
        """Length of the key in bits."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_key_bitlen(self.ctx)
        return result

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_encrypted_len(self.ctx, data_len)
        return result

    def export_public_key(self):
        """Export public key in the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        out = Buffer(self.exported_public_key_len())
        status = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_export_public_key(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def exported_public_key_len(self):
        """Return length in bytes required to hold exported public key."""
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_exported_public_key_len(self.ctx)
        return result

    def import_public_key(self, data):
        """Import public key from the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be imported from the format defined in
        RFC 3447 Appendix A.1.1."""
        d_data = Data(data)
        status = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_import_public_key(self.ctx, d_data.data)
        VscfStatus.handle_status(status)

    def generate_ephemeral_key(self):
        """Generate ephemeral private key of the same type."""
        error = vscf_error_t()
        result = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_generate_ephemeral_key(self.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_curve25519_public_key = VscfCurve25519PublicKey()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_curve25519_public_key = VscfCurve25519PublicKey()
        inst.ctx = inst._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_shallow_copy(value)
        self._c_impl = self._lib_vscf_curve25519_public_key.vscf_curve25519_public_key_impl(self.ctx)