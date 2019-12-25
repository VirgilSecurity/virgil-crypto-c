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
from ._c_bridge import VscfFalcon
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from ._c_bridge._vscf_error import vscf_error_t
from virgil_crypto_lib.common._c_bridge import Data
from .raw_public_key import RawPublicKey
from virgil_crypto_lib.common._c_bridge import Buffer
from .raw_private_key import RawPrivateKey
from .alg import Alg
from .key_alg import KeyAlg
from .key_signer import KeySigner


class Falcon(Alg, KeyAlg, KeySigner):
    """Provide post-quantum signature based on the falcon implementation.
    For algorithm details check https://falcon-sign.info."""

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
        self._lib_vscf_falcon = VscfFalcon()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_falcon.vscf_falcon_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_falcon.vscf_falcon_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_falcon.vscf_falcon_use_random(self.ctx, random.c_impl)

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_falcon.vscf_falcon_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_falcon.vscf_falcon_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_falcon.vscf_falcon_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def generate_ephemeral_key(self, key):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_generate_ephemeral_key(self.ctx, key.c_impl, error)
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
        result = self._lib_vscf_falcon.vscf_falcon_import_public_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_public_key_data(self, key_data, key_alg_info):
        """Import public key from the raw binary format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_import_public_key_data(self.ctx, d_key_data.data, key_alg_info.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_public_key(self, public_key):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_export_public_key(self.ctx, public_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPublicKey.take_c_ctx(result)
        return instance

    def exported_public_key_data_len(self, public_key):
        """Return length in bytes required to hold exported public key."""
        result = self._lib_vscf_falcon.vscf_falcon_exported_public_key_data_len(self.ctx, public_key.c_impl)
        return result

    def export_public_key_data(self, public_key):
        """Export public key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        out = Buffer(self.exported_public_key_data_len(public_key=public_key))
        status = self._lib_vscf_falcon.vscf_falcon_export_public_key_data(self.ctx, public_key.c_impl, out.c_buffer)
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
        result = self._lib_vscf_falcon.vscf_falcon_import_private_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_private_key_data(self, key_data, key_alg_info):
        """Import private key from the raw binary format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_import_private_key_data(self.ctx, d_key_data.data, key_alg_info.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_private_key(self, private_key):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_export_private_key(self.ctx, private_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPrivateKey.take_c_ctx(result)
        return instance

    def exported_private_key_data_len(self, private_key):
        """Return length in bytes required to hold exported private key."""
        result = self._lib_vscf_falcon.vscf_falcon_exported_private_key_data_len(self.ctx, private_key.c_impl)
        return result

    def export_private_key_data(self, private_key):
        """Export private key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        out = Buffer(self.exported_private_key_data_len(private_key=private_key))
        status = self._lib_vscf_falcon.vscf_falcon_export_private_key_data(self.ctx, private_key.c_impl, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def can_sign(self, private_key):
        """Check if algorithm can sign data digest with a given key."""
        result = self._lib_vscf_falcon.vscf_falcon_can_sign(self.ctx, private_key.c_impl)
        return result

    def signature_len(self, private_key):
        """Return length in bytes required to hold signature.
        Return zero if a given private key can not produce signatures."""
        result = self._lib_vscf_falcon.vscf_falcon_signature_len(self.ctx, private_key.c_impl)
        return result

    def sign_hash(self, private_key, hash_id, digest):
        """Sign data digest with a given private key."""
        d_digest = Data(digest)
        signature = Buffer(self.signature_len(private_key=private_key))
        status = self._lib_vscf_falcon.vscf_falcon_sign_hash(self.ctx, private_key.c_impl, hash_id, d_digest.data, signature.c_buffer)
        VscfStatus.handle_status(status)
        return signature.get_bytes()

    def can_verify(self, public_key):
        """Check if algorithm can verify data digest with a given key."""
        result = self._lib_vscf_falcon.vscf_falcon_can_verify(self.ctx, public_key.c_impl)
        return result

    def verify_hash(self, public_key, hash_id, digest, signature):
        """Verify data digest with a given public key and signature."""
        d_digest = Data(digest)
        d_signature = Data(signature)
        result = self._lib_vscf_falcon.vscf_falcon_verify_hash(self.ctx, public_key.c_impl, hash_id, d_digest.data, d_signature.data)
        return result

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_falcon.vscf_falcon_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def generate_key(self):
        """Generate new private key.
        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_falcon.vscf_falcon_generate_key(self.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_falcon = VscfFalcon()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_falcon = VscfFalcon()
        inst.ctx = inst._lib_vscf_falcon.vscf_falcon_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_falcon.vscf_falcon_shallow_copy(value)
        self._c_impl = self._lib_vscf_falcon.vscf_falcon_impl(self.ctx)
