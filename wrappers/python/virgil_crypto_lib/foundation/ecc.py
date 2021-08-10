# Copyright (C) 2015-2021 Virgil Security, Inc.
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
from ._c_bridge import VscfEcc
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from .raw_public_key import RawPublicKey
from .raw_private_key import RawPrivateKey
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .key_alg import KeyAlg
from .key_cipher import KeyCipher
from .key_signer import KeySigner
from .compute_shared_key import ComputeSharedKey
from .kem import Kem


class Ecc(KeyAlg, KeyCipher, KeySigner, ComputeSharedKey, Kem):
    """Elliptic curve cryptography implementation.
    Supported curves:
        - secp256r1."""

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
        self._lib_vscf_ecc = VscfEcc()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_ecc.vscf_ecc_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_ecc.vscf_ecc_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_ecc.vscf_ecc_use_random(self.ctx, random.c_impl)

    def set_ecies(self, ecies):
        self._lib_vscf_ecc.vscf_ecc_use_ecies(self.ctx, ecies.ctx)

    def generate_ephemeral_key(self, key):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_ecc.vscf_ecc_generate_ephemeral_key(self.ctx, key.c_impl, error)
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
        result = self._lib_vscf_ecc.vscf_ecc_import_public_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_public_key(self, public_key):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        error = vscf_error_t()
        result = self._lib_vscf_ecc.vscf_ecc_export_public_key(self.ctx, public_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPublicKey.take_c_ctx(result)
        return instance

    def import_private_key(self, raw_key):
        """Import private key from the raw binary format.

        Return private key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        error = vscf_error_t()
        result = self._lib_vscf_ecc.vscf_ecc_import_private_key(self.ctx, raw_key.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def export_private_key(self, private_key):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        error = vscf_error_t()
        result = self._lib_vscf_ecc.vscf_ecc_export_private_key(self.ctx, private_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = RawPrivateKey.take_c_ctx(result)
        return instance

    def can_encrypt(self, public_key, data_len):
        """Check if algorithm can encrypt data with a given key."""
        result = self._lib_vscf_ecc.vscf_ecc_can_encrypt(self.ctx, public_key.c_impl, data_len)
        return result

    def encrypted_len(self, public_key, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_ecc.vscf_ecc_encrypted_len(self.ctx, public_key.c_impl, data_len)
        return result

    def encrypt(self, public_key, data):
        """Encrypt data with a given public key."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(public_key=public_key, data_len=len(data)))
        status = self._lib_vscf_ecc.vscf_ecc_encrypt(self.ctx, public_key.c_impl, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def can_decrypt(self, private_key, data_len):
        """Check if algorithm can decrypt data with a given key.
        However, success result of decryption is not guaranteed."""
        result = self._lib_vscf_ecc.vscf_ecc_can_decrypt(self.ctx, private_key.c_impl, data_len)
        return result

    def decrypted_len(self, private_key, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_ecc.vscf_ecc_decrypted_len(self.ctx, private_key.c_impl, data_len)
        return result

    def decrypt(self, private_key, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(private_key=private_key, data_len=len(data)))
        status = self._lib_vscf_ecc.vscf_ecc_decrypt(self.ctx, private_key.c_impl, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def can_sign(self, private_key):
        """Check if algorithm can sign data digest with a given key."""
        result = self._lib_vscf_ecc.vscf_ecc_can_sign(self.ctx, private_key.c_impl)
        return result

    def signature_len(self, private_key):
        """Return length in bytes required to hold signature.
        Return zero if a given private key can not produce signatures."""
        result = self._lib_vscf_ecc.vscf_ecc_signature_len(self.ctx, private_key.c_impl)
        return result

    def sign_hash(self, private_key, hash_id, digest):
        """Sign data digest with a given private key."""
        d_digest = Data(digest)
        signature = Buffer(self.signature_len(private_key=private_key))
        status = self._lib_vscf_ecc.vscf_ecc_sign_hash(self.ctx, private_key.c_impl, hash_id, d_digest.data, signature.c_buffer)
        VscfStatus.handle_status(status)
        return signature.get_bytes()

    def can_verify(self, public_key):
        """Check if algorithm can verify data digest with a given key."""
        result = self._lib_vscf_ecc.vscf_ecc_can_verify(self.ctx, public_key.c_impl)
        return result

    def verify_hash(self, public_key, hash_id, digest, signature):
        """Verify data digest with a given public key and signature."""
        d_digest = Data(digest)
        d_signature = Data(signature)
        result = self._lib_vscf_ecc.vscf_ecc_verify_hash(self.ctx, public_key.c_impl, hash_id, d_digest.data, d_signature.data)
        return result

    def compute_shared_key(self, public_key, private_key):
        """Compute shared key for 2 asymmetric keys.
        Note, computed shared key can be used only within symmetric cryptography."""
        shared_key = Buffer(self.shared_key_len(key=private_key))
        status = self._lib_vscf_ecc.vscf_ecc_compute_shared_key(self.ctx, public_key.c_impl, private_key.c_impl, shared_key.c_buffer)
        VscfStatus.handle_status(status)
        return shared_key.get_bytes()

    def shared_key_len(self, key):
        """Return number of bytes required to hold shared key.
        Expect Public Key or Private Key."""
        result = self._lib_vscf_ecc.vscf_ecc_shared_key_len(self.ctx, key.c_impl)
        return result

    def kem_shared_key_len(self, key):
        """Return length in bytes required to hold encapsulated shared key."""
        result = self._lib_vscf_ecc.vscf_ecc_kem_shared_key_len(self.ctx, key.c_impl)
        return result

    def kem_encapsulated_key_len(self, public_key):
        """Return length in bytes required to hold encapsulated key."""
        result = self._lib_vscf_ecc.vscf_ecc_kem_encapsulated_key_len(self.ctx, public_key.c_impl)
        return result

    def kem_encapsulate(self, public_key):
        """Generate a shared key and a key encapsulated message."""
        shared_key = Buffer(self.kem_shared_key_len(key=public_key))
        encapsulated_key = Buffer(self.kem_encapsulated_key_len(public_key=public_key))
        status = self._lib_vscf_ecc.vscf_ecc_kem_encapsulate(self.ctx, public_key.c_impl, shared_key.c_buffer, encapsulated_key.c_buffer)
        VscfStatus.handle_status(status)
        return shared_key.get_bytes(), encapsulated_key.get_bytes()

    def kem_decapsulate(self, encapsulated_key, private_key):
        """Decapsulate the shared key."""
        d_encapsulated_key = Data(encapsulated_key)
        shared_key = Buffer(self.kem_shared_key_len(key=private_key))
        status = self._lib_vscf_ecc.vscf_ecc_kem_decapsulate(self.ctx, d_encapsulated_key.data, private_key.c_impl, shared_key.c_buffer)
        VscfStatus.handle_status(status)
        return shared_key.get_bytes()

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_ecc.vscf_ecc_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def generate_key(self, alg_id):
        """Generate new private key.
        Supported algorithm ids:
            - secp256r1.

        Note, this operation might be slow."""
        error = vscf_error_t()
        result = self._lib_vscf_ecc.vscf_ecc_generate_key(self.ctx, alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecc = VscfEcc()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecc = VscfEcc()
        inst.ctx = inst._lib_vscf_ecc.vscf_ecc_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_ecc.vscf_ecc_shallow_copy(value)
        self._c_impl = self._lib_vscf_ecc.vscf_ecc_impl(self.ctx)
