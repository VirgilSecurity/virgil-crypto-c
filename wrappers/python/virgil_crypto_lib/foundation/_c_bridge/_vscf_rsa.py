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
from ._vscf_error import vscf_error_t
from ._vscf_raw_public_key import vscf_raw_public_key_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_raw_private_key import vscf_raw_private_key_t


class vscf_rsa_t(Structure):
    pass


class VscfRsa(object):
    """RSA implementation."""

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
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_rsa_new(self):
        vscf_rsa_new = self._lib.vscf_rsa_new
        vscf_rsa_new.argtypes = []
        vscf_rsa_new.restype = POINTER(vscf_rsa_t)
        return vscf_rsa_new()

    def vscf_rsa_delete(self, ctx):
        vscf_rsa_delete = self._lib.vscf_rsa_delete
        vscf_rsa_delete.argtypes = [POINTER(vscf_rsa_t)]
        vscf_rsa_delete.restype = None
        return vscf_rsa_delete(ctx)

    def vscf_rsa_use_random(self, ctx, random):
        vscf_rsa_use_random = self._lib.vscf_rsa_use_random
        vscf_rsa_use_random.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_use_random.restype = None
        return vscf_rsa_use_random(ctx, random)

    def vscf_rsa_generate_ephemeral_key(self, ctx, key, error):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        vscf_rsa_generate_ephemeral_key = self._lib.vscf_rsa_generate_ephemeral_key
        vscf_rsa_generate_ephemeral_key.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_rsa_generate_ephemeral_key.restype = POINTER(vscf_impl_t)
        return vscf_rsa_generate_ephemeral_key(ctx, key, error)

    def vscf_rsa_import_public_key(self, ctx, raw_key, error):
        """Import public key from the raw binary format.

        Return public key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be imported from the format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_rsa_import_public_key = self._lib.vscf_rsa_import_public_key
        vscf_rsa_import_public_key.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_raw_public_key_t), POINTER(vscf_error_t)]
        vscf_rsa_import_public_key.restype = POINTER(vscf_impl_t)
        return vscf_rsa_import_public_key(ctx, raw_key, error)

    def vscf_rsa_import_public_key_data(self, ctx, key_data, key_alg_info, error):
        """Import public key from the raw binary format."""
        vscf_rsa_import_public_key_data = self._lib.vscf_rsa_import_public_key_data
        vscf_rsa_import_public_key_data.argtypes = [POINTER(vscf_rsa_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_rsa_import_public_key_data.restype = POINTER(vscf_impl_t)
        return vscf_rsa_import_public_key_data(ctx, key_data, key_alg_info, error)

    def vscf_rsa_export_public_key(self, ctx, public_key, error):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_rsa_export_public_key = self._lib.vscf_rsa_export_public_key
        vscf_rsa_export_public_key.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_rsa_export_public_key.restype = POINTER(vscf_raw_public_key_t)
        return vscf_rsa_export_public_key(ctx, public_key, error)

    def vscf_rsa_exported_public_key_data_len(self, ctx, public_key):
        """Return length in bytes required to hold exported public key."""
        vscf_rsa_exported_public_key_data_len = self._lib.vscf_rsa_exported_public_key_data_len
        vscf_rsa_exported_public_key_data_len.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_exported_public_key_data_len.restype = c_size_t
        return vscf_rsa_exported_public_key_data_len(ctx, public_key)

    def vscf_rsa_export_public_key_data(self, ctx, public_key, out):
        """Export public key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_rsa_export_public_key_data = self._lib.vscf_rsa_export_public_key_data
        vscf_rsa_export_public_key_data.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_rsa_export_public_key_data.restype = c_int
        return vscf_rsa_export_public_key_data(ctx, public_key, out)

    def vscf_rsa_import_private_key(self, ctx, raw_key, error):
        """Import private key from the raw binary format.

        Return private key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_rsa_import_private_key = self._lib.vscf_rsa_import_private_key
        vscf_rsa_import_private_key.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_raw_private_key_t), POINTER(vscf_error_t)]
        vscf_rsa_import_private_key.restype = POINTER(vscf_impl_t)
        return vscf_rsa_import_private_key(ctx, raw_key, error)

    def vscf_rsa_import_private_key_data(self, ctx, key_data, key_alg_info, error):
        """Import private key from the raw binary format."""
        vscf_rsa_import_private_key_data = self._lib.vscf_rsa_import_private_key_data
        vscf_rsa_import_private_key_data.argtypes = [POINTER(vscf_rsa_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_rsa_import_private_key_data.restype = POINTER(vscf_impl_t)
        return vscf_rsa_import_private_key_data(ctx, key_data, key_alg_info, error)

    def vscf_rsa_export_private_key(self, ctx, private_key, error):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_rsa_export_private_key = self._lib.vscf_rsa_export_private_key
        vscf_rsa_export_private_key.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_rsa_export_private_key.restype = POINTER(vscf_raw_private_key_t)
        return vscf_rsa_export_private_key(ctx, private_key, error)

    def vscf_rsa_exported_private_key_data_len(self, ctx, private_key):
        """Return length in bytes required to hold exported private key."""
        vscf_rsa_exported_private_key_data_len = self._lib.vscf_rsa_exported_private_key_data_len
        vscf_rsa_exported_private_key_data_len.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_exported_private_key_data_len.restype = c_size_t
        return vscf_rsa_exported_private_key_data_len(ctx, private_key)

    def vscf_rsa_export_private_key_data(self, ctx, private_key, out):
        """Export private key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_rsa_export_private_key_data = self._lib.vscf_rsa_export_private_key_data
        vscf_rsa_export_private_key_data.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_rsa_export_private_key_data.restype = c_int
        return vscf_rsa_export_private_key_data(ctx, private_key, out)

    def vscf_rsa_can_encrypt(self, ctx, public_key, data_len):
        """Check if algorithm can encrypt data with a given key."""
        vscf_rsa_can_encrypt = self._lib.vscf_rsa_can_encrypt
        vscf_rsa_can_encrypt.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_size_t]
        vscf_rsa_can_encrypt.restype = c_bool
        return vscf_rsa_can_encrypt(ctx, public_key, data_len)

    def vscf_rsa_encrypted_len(self, ctx, public_key, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        vscf_rsa_encrypted_len = self._lib.vscf_rsa_encrypted_len
        vscf_rsa_encrypted_len.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_size_t]
        vscf_rsa_encrypted_len.restype = c_size_t
        return vscf_rsa_encrypted_len(ctx, public_key, data_len)

    def vscf_rsa_encrypt(self, ctx, public_key, data, out):
        """Encrypt data with a given public key."""
        vscf_rsa_encrypt = self._lib.vscf_rsa_encrypt
        vscf_rsa_encrypt.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_rsa_encrypt.restype = c_int
        return vscf_rsa_encrypt(ctx, public_key, data, out)

    def vscf_rsa_can_decrypt(self, ctx, private_key, data_len):
        """Check if algorithm can decrypt data with a given key.
        However, success result of decryption is not guaranteed."""
        vscf_rsa_can_decrypt = self._lib.vscf_rsa_can_decrypt
        vscf_rsa_can_decrypt.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_size_t]
        vscf_rsa_can_decrypt.restype = c_bool
        return vscf_rsa_can_decrypt(ctx, private_key, data_len)

    def vscf_rsa_decrypted_len(self, ctx, private_key, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_rsa_decrypted_len = self._lib.vscf_rsa_decrypted_len
        vscf_rsa_decrypted_len.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_size_t]
        vscf_rsa_decrypted_len.restype = c_size_t
        return vscf_rsa_decrypted_len(ctx, private_key, data_len)

    def vscf_rsa_decrypt(self, ctx, private_key, data, out):
        """Decrypt given data."""
        vscf_rsa_decrypt = self._lib.vscf_rsa_decrypt
        vscf_rsa_decrypt.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_rsa_decrypt.restype = c_int
        return vscf_rsa_decrypt(ctx, private_key, data, out)

    def vscf_rsa_can_sign(self, ctx, private_key):
        """Check if algorithm can sign data digest with a given key."""
        vscf_rsa_can_sign = self._lib.vscf_rsa_can_sign
        vscf_rsa_can_sign.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_can_sign.restype = c_bool
        return vscf_rsa_can_sign(ctx, private_key)

    def vscf_rsa_signature_len(self, ctx, private_key):
        """Return length in bytes required to hold signature.
        Return zero if a given private key can not produce signatures."""
        vscf_rsa_signature_len = self._lib.vscf_rsa_signature_len
        vscf_rsa_signature_len.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_signature_len.restype = c_size_t
        return vscf_rsa_signature_len(ctx, private_key)

    def vscf_rsa_sign_hash(self, ctx, private_key, hash_id, digest, signature):
        """Sign data digest with a given private key."""
        vscf_rsa_sign_hash = self._lib.vscf_rsa_sign_hash
        vscf_rsa_sign_hash.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_int, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_rsa_sign_hash.restype = c_int
        return vscf_rsa_sign_hash(ctx, private_key, hash_id, digest, signature)

    def vscf_rsa_can_verify(self, ctx, public_key):
        """Check if algorithm can verify data digest with a given key."""
        vscf_rsa_can_verify = self._lib.vscf_rsa_can_verify
        vscf_rsa_can_verify.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t)]
        vscf_rsa_can_verify.restype = c_bool
        return vscf_rsa_can_verify(ctx, public_key)

    def vscf_rsa_verify_hash(self, ctx, public_key, hash_id, digest, signature):
        """Verify data digest with a given public key and signature."""
        vscf_rsa_verify_hash = self._lib.vscf_rsa_verify_hash
        vscf_rsa_verify_hash.argtypes = [POINTER(vscf_rsa_t), POINTER(vscf_impl_t), c_int, vsc_data_t, vsc_data_t]
        vscf_rsa_verify_hash.restype = c_bool
        return vscf_rsa_verify_hash(ctx, public_key, hash_id, digest, signature)

    def vscf_rsa_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_rsa_setup_defaults = self._lib.vscf_rsa_setup_defaults
        vscf_rsa_setup_defaults.argtypes = [POINTER(vscf_rsa_t)]
        vscf_rsa_setup_defaults.restype = c_int
        return vscf_rsa_setup_defaults(ctx)

    def vscf_rsa_generate_key(self, ctx, bitlen, error):
        """Generate new private key.
        Note, this operation might be slow."""
        vscf_rsa_generate_key = self._lib.vscf_rsa_generate_key
        vscf_rsa_generate_key.argtypes = [POINTER(vscf_rsa_t), c_size_t, POINTER(vscf_error_t)]
        vscf_rsa_generate_key.restype = POINTER(vscf_impl_t)
        return vscf_rsa_generate_key(ctx, bitlen, error)

    def vscf_rsa_shallow_copy(self, ctx):
        vscf_rsa_shallow_copy = self._lib.vscf_rsa_shallow_copy
        vscf_rsa_shallow_copy.argtypes = [POINTER(vscf_rsa_t)]
        vscf_rsa_shallow_copy.restype = POINTER(vscf_rsa_t)
        return vscf_rsa_shallow_copy(ctx)

    def vscf_rsa_impl(self, ctx):
        vscf_rsa_impl = self._lib.vscf_rsa_impl
        vscf_rsa_impl.argtypes = [POINTER(vscf_rsa_t)]
        vscf_rsa_impl.restype = POINTER(vscf_impl_t)
        return vscf_rsa_impl(ctx)
