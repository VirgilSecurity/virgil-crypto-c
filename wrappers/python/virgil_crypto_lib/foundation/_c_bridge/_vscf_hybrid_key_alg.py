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


class vscf_hybrid_key_alg_t(Structure):
    pass


class VscfHybridKeyAlg(object):
    """Implements public key cryptography over hybrid keys.
    Hybrid encryption - TODO
    Hybrid signatures - TODO"""

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

    def vscf_hybrid_key_alg_new(self):
        vscf_hybrid_key_alg_new = self._lib.vscf_hybrid_key_alg_new
        vscf_hybrid_key_alg_new.argtypes = []
        vscf_hybrid_key_alg_new.restype = POINTER(vscf_hybrid_key_alg_t)
        return vscf_hybrid_key_alg_new()

    def vscf_hybrid_key_alg_delete(self, ctx):
        vscf_hybrid_key_alg_delete = self._lib.vscf_hybrid_key_alg_delete
        vscf_hybrid_key_alg_delete.argtypes = [POINTER(vscf_hybrid_key_alg_t)]
        vscf_hybrid_key_alg_delete.restype = None
        return vscf_hybrid_key_alg_delete(ctx)

    def vscf_hybrid_key_alg_use_random(self, ctx, random):
        vscf_hybrid_key_alg_use_random = self._lib.vscf_hybrid_key_alg_use_random
        vscf_hybrid_key_alg_use_random.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_use_random.restype = None
        return vscf_hybrid_key_alg_use_random(ctx, random)

    def vscf_hybrid_key_alg_use_cipher(self, ctx, cipher):
        vscf_hybrid_key_alg_use_cipher = self._lib.vscf_hybrid_key_alg_use_cipher
        vscf_hybrid_key_alg_use_cipher.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_use_cipher.restype = None
        return vscf_hybrid_key_alg_use_cipher(ctx, cipher)

    def vscf_hybrid_key_alg_use_hash(self, ctx, hash):
        vscf_hybrid_key_alg_use_hash = self._lib.vscf_hybrid_key_alg_use_hash
        vscf_hybrid_key_alg_use_hash.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_use_hash.restype = None
        return vscf_hybrid_key_alg_use_hash(ctx, hash)

    def vscf_hybrid_key_alg_generate_ephemeral_key(self, ctx, key, error):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        vscf_hybrid_key_alg_generate_ephemeral_key = self._lib.vscf_hybrid_key_alg_generate_ephemeral_key
        vscf_hybrid_key_alg_generate_ephemeral_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_generate_ephemeral_key.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_generate_ephemeral_key(ctx, key, error)

    def vscf_hybrid_key_alg_import_public_key(self, ctx, raw_key, error):
        """Import public key from the raw binary format.

        Return public key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be imported from the format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_hybrid_key_alg_import_public_key = self._lib.vscf_hybrid_key_alg_import_public_key
        vscf_hybrid_key_alg_import_public_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_raw_public_key_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_import_public_key.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_import_public_key(ctx, raw_key, error)

    def vscf_hybrid_key_alg_import_public_key_data(self, ctx, key_data, key_alg_info, error):
        """Import public key from the raw binary format."""
        vscf_hybrid_key_alg_import_public_key_data = self._lib.vscf_hybrid_key_alg_import_public_key_data
        vscf_hybrid_key_alg_import_public_key_data.argtypes = [POINTER(vscf_hybrid_key_alg_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_import_public_key_data.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_import_public_key_data(ctx, key_data, key_alg_info, error)

    def vscf_hybrid_key_alg_export_public_key(self, ctx, public_key, error):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_hybrid_key_alg_export_public_key = self._lib.vscf_hybrid_key_alg_export_public_key
        vscf_hybrid_key_alg_export_public_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_export_public_key.restype = POINTER(vscf_raw_public_key_t)
        return vscf_hybrid_key_alg_export_public_key(ctx, public_key, error)

    def vscf_hybrid_key_alg_exported_public_key_data_len(self, ctx, public_key):
        """Return length in bytes required to hold exported public key."""
        vscf_hybrid_key_alg_exported_public_key_data_len = self._lib.vscf_hybrid_key_alg_exported_public_key_data_len
        vscf_hybrid_key_alg_exported_public_key_data_len.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_exported_public_key_data_len.restype = c_size_t
        return vscf_hybrid_key_alg_exported_public_key_data_len(ctx, public_key)

    def vscf_hybrid_key_alg_export_public_key_data(self, ctx, public_key, out):
        """Export public key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_hybrid_key_alg_export_public_key_data = self._lib.vscf_hybrid_key_alg_export_public_key_data
        vscf_hybrid_key_alg_export_public_key_data.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_hybrid_key_alg_export_public_key_data.restype = c_int
        return vscf_hybrid_key_alg_export_public_key_data(ctx, public_key, out)

    def vscf_hybrid_key_alg_import_private_key(self, ctx, raw_key, error):
        """Import private key from the raw binary format.

        Return private key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_hybrid_key_alg_import_private_key = self._lib.vscf_hybrid_key_alg_import_private_key
        vscf_hybrid_key_alg_import_private_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_raw_private_key_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_import_private_key.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_import_private_key(ctx, raw_key, error)

    def vscf_hybrid_key_alg_import_private_key_data(self, ctx, key_data, key_alg_info, error):
        """Import private key from the raw binary format."""
        vscf_hybrid_key_alg_import_private_key_data = self._lib.vscf_hybrid_key_alg_import_private_key_data
        vscf_hybrid_key_alg_import_private_key_data.argtypes = [POINTER(vscf_hybrid_key_alg_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_import_private_key_data.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_import_private_key_data(ctx, key_data, key_alg_info, error)

    def vscf_hybrid_key_alg_export_private_key(self, ctx, private_key, error):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_hybrid_key_alg_export_private_key = self._lib.vscf_hybrid_key_alg_export_private_key
        vscf_hybrid_key_alg_export_private_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_export_private_key.restype = POINTER(vscf_raw_private_key_t)
        return vscf_hybrid_key_alg_export_private_key(ctx, private_key, error)

    def vscf_hybrid_key_alg_exported_private_key_data_len(self, ctx, private_key):
        """Return length in bytes required to hold exported private key."""
        vscf_hybrid_key_alg_exported_private_key_data_len = self._lib.vscf_hybrid_key_alg_exported_private_key_data_len
        vscf_hybrid_key_alg_exported_private_key_data_len.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_exported_private_key_data_len.restype = c_size_t
        return vscf_hybrid_key_alg_exported_private_key_data_len(ctx, private_key)

    def vscf_hybrid_key_alg_export_private_key_data(self, ctx, private_key, out):
        """Export private key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_hybrid_key_alg_export_private_key_data = self._lib.vscf_hybrid_key_alg_export_private_key_data
        vscf_hybrid_key_alg_export_private_key_data.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_hybrid_key_alg_export_private_key_data.restype = c_int
        return vscf_hybrid_key_alg_export_private_key_data(ctx, private_key, out)

    def vscf_hybrid_key_alg_can_encrypt(self, ctx, public_key, data_len):
        """Check if algorithm can encrypt data with a given key."""
        vscf_hybrid_key_alg_can_encrypt = self._lib.vscf_hybrid_key_alg_can_encrypt
        vscf_hybrid_key_alg_can_encrypt.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_size_t]
        vscf_hybrid_key_alg_can_encrypt.restype = c_bool
        return vscf_hybrid_key_alg_can_encrypt(ctx, public_key, data_len)

    def vscf_hybrid_key_alg_encrypted_len(self, ctx, public_key, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        vscf_hybrid_key_alg_encrypted_len = self._lib.vscf_hybrid_key_alg_encrypted_len
        vscf_hybrid_key_alg_encrypted_len.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_size_t]
        vscf_hybrid_key_alg_encrypted_len.restype = c_size_t
        return vscf_hybrid_key_alg_encrypted_len(ctx, public_key, data_len)

    def vscf_hybrid_key_alg_encrypt(self, ctx, public_key, data, out):
        """Encrypt data with a given public key."""
        vscf_hybrid_key_alg_encrypt = self._lib.vscf_hybrid_key_alg_encrypt
        vscf_hybrid_key_alg_encrypt.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_hybrid_key_alg_encrypt.restype = c_int
        return vscf_hybrid_key_alg_encrypt(ctx, public_key, data, out)

    def vscf_hybrid_key_alg_can_decrypt(self, ctx, private_key, data_len):
        """Check if algorithm can decrypt data with a given key.
        However, success result of decryption is not guaranteed."""
        vscf_hybrid_key_alg_can_decrypt = self._lib.vscf_hybrid_key_alg_can_decrypt
        vscf_hybrid_key_alg_can_decrypt.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_size_t]
        vscf_hybrid_key_alg_can_decrypt.restype = c_bool
        return vscf_hybrid_key_alg_can_decrypt(ctx, private_key, data_len)

    def vscf_hybrid_key_alg_decrypted_len(self, ctx, private_key, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_hybrid_key_alg_decrypted_len = self._lib.vscf_hybrid_key_alg_decrypted_len
        vscf_hybrid_key_alg_decrypted_len.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_size_t]
        vscf_hybrid_key_alg_decrypted_len.restype = c_size_t
        return vscf_hybrid_key_alg_decrypted_len(ctx, private_key, data_len)

    def vscf_hybrid_key_alg_decrypt(self, ctx, private_key, data, out):
        """Decrypt given data."""
        vscf_hybrid_key_alg_decrypt = self._lib.vscf_hybrid_key_alg_decrypt
        vscf_hybrid_key_alg_decrypt.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_hybrid_key_alg_decrypt.restype = c_int
        return vscf_hybrid_key_alg_decrypt(ctx, private_key, data, out)

    def vscf_hybrid_key_alg_can_sign(self, ctx, private_key):
        """Check if algorithm can sign data digest with a given key."""
        vscf_hybrid_key_alg_can_sign = self._lib.vscf_hybrid_key_alg_can_sign
        vscf_hybrid_key_alg_can_sign.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_can_sign.restype = c_bool
        return vscf_hybrid_key_alg_can_sign(ctx, private_key)

    def vscf_hybrid_key_alg_signature_len(self, ctx, private_key):
        """Return length in bytes required to hold signature.
        Return zero if a given private key can not produce signatures."""
        vscf_hybrid_key_alg_signature_len = self._lib.vscf_hybrid_key_alg_signature_len
        vscf_hybrid_key_alg_signature_len.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_signature_len.restype = c_size_t
        return vscf_hybrid_key_alg_signature_len(ctx, private_key)

    def vscf_hybrid_key_alg_sign_hash(self, ctx, private_key, hash_id, digest, signature):
        """Sign data digest with a given private key."""
        vscf_hybrid_key_alg_sign_hash = self._lib.vscf_hybrid_key_alg_sign_hash
        vscf_hybrid_key_alg_sign_hash.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_int, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_hybrid_key_alg_sign_hash.restype = c_int
        return vscf_hybrid_key_alg_sign_hash(ctx, private_key, hash_id, digest, signature)

    def vscf_hybrid_key_alg_can_verify(self, ctx, public_key):
        """Check if algorithm can verify data digest with a given key."""
        vscf_hybrid_key_alg_can_verify = self._lib.vscf_hybrid_key_alg_can_verify
        vscf_hybrid_key_alg_can_verify.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t)]
        vscf_hybrid_key_alg_can_verify.restype = c_bool
        return vscf_hybrid_key_alg_can_verify(ctx, public_key)

    def vscf_hybrid_key_alg_verify_hash(self, ctx, public_key, hash_id, digest, signature):
        """Verify data digest with a given public key and signature."""
        vscf_hybrid_key_alg_verify_hash = self._lib.vscf_hybrid_key_alg_verify_hash
        vscf_hybrid_key_alg_verify_hash.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), c_int, vsc_data_t, vsc_data_t]
        vscf_hybrid_key_alg_verify_hash.restype = c_bool
        return vscf_hybrid_key_alg_verify_hash(ctx, public_key, hash_id, digest, signature)

    def vscf_hybrid_key_alg_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_hybrid_key_alg_setup_defaults = self._lib.vscf_hybrid_key_alg_setup_defaults
        vscf_hybrid_key_alg_setup_defaults.argtypes = [POINTER(vscf_hybrid_key_alg_t)]
        vscf_hybrid_key_alg_setup_defaults.restype = c_int
        return vscf_hybrid_key_alg_setup_defaults(ctx)

    def vscf_hybrid_key_alg_make_key(self, ctx, first_key, second_key, error):
        """Make hybrid private key from given keys."""
        vscf_hybrid_key_alg_make_key = self._lib.vscf_hybrid_key_alg_make_key
        vscf_hybrid_key_alg_make_key.argtypes = [POINTER(vscf_hybrid_key_alg_t), POINTER(vscf_impl_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_hybrid_key_alg_make_key.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_make_key(ctx, first_key, second_key, error)

    def vscf_hybrid_key_alg_shallow_copy(self, ctx):
        vscf_hybrid_key_alg_shallow_copy = self._lib.vscf_hybrid_key_alg_shallow_copy
        vscf_hybrid_key_alg_shallow_copy.argtypes = [POINTER(vscf_hybrid_key_alg_t)]
        vscf_hybrid_key_alg_shallow_copy.restype = POINTER(vscf_hybrid_key_alg_t)
        return vscf_hybrid_key_alg_shallow_copy(ctx)

    def vscf_hybrid_key_alg_impl(self, ctx):
        vscf_hybrid_key_alg_impl = self._lib.vscf_hybrid_key_alg_impl
        vscf_hybrid_key_alg_impl.argtypes = [POINTER(vscf_hybrid_key_alg_t)]
        vscf_hybrid_key_alg_impl.restype = POINTER(vscf_impl_t)
        return vscf_hybrid_key_alg_impl(ctx)
