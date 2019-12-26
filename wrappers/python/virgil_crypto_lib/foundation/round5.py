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
from ._c_bridge import VscfRound5
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from .raw_public_key import RawPublicKey
from virgil_crypto_lib.common._c_bridge import Buffer
from .raw_private_key import RawPrivateKey
from .key_alg import KeyAlg
from .kem import Kem


class Round5(KeyAlg, Kem):
    """Provide post-quantum encryption based on the round5 implementation.
    For algorithm details check https://github.com/round5/code"""

    # Defines whether a public key can be imported or not.
    CAN_IMPORT_PUBLIC_KEY = True
    # Define whether a public key can be exported or not.
    CAN_EXPORT_PUBLIC_KEY = True
    # Define whether a private key can be imported or not.
    CAN_IMPORT_PRIVATE_KEY = True
    # Define whether a private key can be exported or not.
    CAN_EXPORT_PRIVATE_KEY = True

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_round5 = VscfRound5()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_round5.vscf_round5_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_round5.vscf_round5_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_round5.vscf_round5_use_random(self.ctx, random.c_impl)

    def generate_ephemeral_key(self, key):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_generate_ephemeral_key(self.ctx, key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_public_key(self, raw_key):
        """Import public key from the raw binary format.

        Return public key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be imported from the format defined in
        RFC 3447 Appendix A.1.1."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_import_public_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_public_key_data(self, key_data, key_alg_info):
        """Import public key from the raw binary format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_import_public_key_data(self.ctx, d_key_data.data, key_alg_info.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_public_key(self, public_key):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_export_public_key(self.ctx, public_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPublicKey.take_c_ctx(result)
        return instance

    def exported_public_key_data_len(self, public_key):
        """Return length in bytes required to hold exported public key."""
        result = self._lib_vscf_round5.vscf_round5_exported_public_key_data_len(self.ctx, public_key.c_impl)
        return result

    def export_public_key_data(self, public_key):
        """Export public key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        out = Buffer(self.exported_public_key_data_len(public_key=public_key))
        status = self._lib_vscf_round5.vscf_round5_export_public_key_data(self.ctx, public_key.c_impl, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def import_private_key(self, raw_key):
        """Import private key from the raw binary format.

        Return private key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_import_private_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_private_key_data(self, key_data, key_alg_info):
        """Import private key from the raw binary format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_import_private_key_data(self.ctx, d_key_data.data, key_alg_info.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_private_key(self, private_key):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_export_private_key(self.ctx, private_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPrivateKey.take_c_ctx(result)
        return instance

    def exported_private_key_data_len(self, private_key):
        """Return length in bytes required to hold exported private key."""
        result = self._lib_vscf_round5.vscf_round5_exported_private_key_data_len(self.ctx, private_key.c_impl)
        return result

    def export_private_key_data(self, private_key):
        """Export private key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        out = Buffer(self.exported_private_key_data_len(private_key=private_key))
        status = self._lib_vscf_round5.vscf_round5_export_private_key_data(self.ctx, private_key.c_impl, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def kem_shared_key_len(self, key):
        """Return length in bytes required to hold encapsulated shared key."""
        result = self._lib_vscf_round5.vscf_round5_kem_shared_key_len(self.ctx, key.c_impl)
        return result

    def kem_encapsulated_key_len(self, public_key):
        """Return length in bytes required to hold encapsulated key."""
        result = self._lib_vscf_round5.vscf_round5_kem_encapsulated_key_len(self.ctx, public_key.c_impl)
        return result

    def kem_encapsulate(self, public_key):
        """Generate a shared key and a key encapsulated message."""
        shared_key = Buffer(self.kem_shared_key_len(key=public_key))
        encapsulated_key = Buffer(self.kem_encapsulated_key_len(public_key=public_key))
        status = self._lib_vscf_round5.vscf_round5_kem_encapsulate(self.ctx, public_key.c_impl, shared_key.c_buffer, encapsulated_key.c_buffer)
        VscfStatus.handle_status(status)
        return shared_key.get_bytes(), encapsulated_key.get_bytes()

    def kem_decapsulate(self, encapsulated_key, private_key):
        """Decapsulate the shared key."""
        d_encapsulated_key = Data(encapsulated_key)
        shared_key = Buffer(self.kem_shared_key_len(key=private_key))
        status = self._lib_vscf_round5.vscf_round5_kem_decapsulate(self.ctx, d_encapsulated_key.data, private_key.c_impl, shared_key.c_buffer)
        VscfStatus.handle_status(status)
        return shared_key.get_bytes()

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_round5.vscf_round5_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def generate_key(self, alg_id):
        """Generate new private key.
        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_round5.vscf_round5_generate_key(self.ctx, alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_round5 = VscfRound5()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_round5 = VscfRound5()
        inst.ctx = inst._lib_vscf_round5.vscf_round5_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_round5.vscf_round5_shallow_copy(value)
        self._c_impl = self._lib_vscf_round5.vscf_round5_impl(self.ctx)
