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
from ._vscf_ecies import vscf_ecies_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_ed25519_private_key_t(Structure):
    pass


class VscfEd25519PrivateKey(object):
    """This is implementation of ED25519 private key"""

    # Define whether a private key can be imported or not.
    CAN_IMPORT_PRIVATE_KEY = True
    # Define whether a private key can be exported or not.
    CAN_EXPORT_PRIVATE_KEY = True

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_ed25519_private_key_new(self):
        vscf_ed25519_private_key_new = self._lib.vscf_ed25519_private_key_new
        vscf_ed25519_private_key_new.argtypes = []
        vscf_ed25519_private_key_new.restype = POINTER(vscf_ed25519_private_key_t)
        return vscf_ed25519_private_key_new()

    def vscf_ed25519_private_key_delete(self, ctx):
        vscf_ed25519_private_key_delete = self._lib.vscf_ed25519_private_key_delete
        vscf_ed25519_private_key_delete.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_delete.restype = None
        return vscf_ed25519_private_key_delete(ctx)

    def vscf_ed25519_private_key_use_random(self, ctx, random):
        vscf_ed25519_private_key_use_random = self._lib.vscf_ed25519_private_key_use_random
        vscf_ed25519_private_key_use_random.argtypes = [POINTER(vscf_ed25519_private_key_t), POINTER(vscf_impl_t)]
        vscf_ed25519_private_key_use_random.restype = None
        return vscf_ed25519_private_key_use_random(ctx, random)

    def vscf_ed25519_private_key_use_ecies(self, ctx, ecies):
        vscf_ed25519_private_key_use_ecies = self._lib.vscf_ed25519_private_key_use_ecies
        vscf_ed25519_private_key_use_ecies.argtypes = [POINTER(vscf_ed25519_private_key_t), POINTER(vscf_ecies_t)]
        vscf_ed25519_private_key_use_ecies.restype = None
        return vscf_ed25519_private_key_use_ecies(ctx, ecies)

    def vscf_ed25519_private_key_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_ed25519_private_key_alg_id = self._lib.vscf_ed25519_private_key_alg_id
        vscf_ed25519_private_key_alg_id.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_alg_id.restype = c_int
        return vscf_ed25519_private_key_alg_id(ctx)

    def vscf_ed25519_private_key_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_ed25519_private_key_produce_alg_info = self._lib.vscf_ed25519_private_key_produce_alg_info
        vscf_ed25519_private_key_produce_alg_info.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_ed25519_private_key_produce_alg_info(ctx)

    def vscf_ed25519_private_key_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_ed25519_private_key_restore_alg_info = self._lib.vscf_ed25519_private_key_restore_alg_info
        vscf_ed25519_private_key_restore_alg_info.argtypes = [POINTER(vscf_ed25519_private_key_t), POINTER(vscf_impl_t)]
        vscf_ed25519_private_key_restore_alg_info.restype = c_int
        return vscf_ed25519_private_key_restore_alg_info(ctx, alg_info)

    def vscf_ed25519_private_key_key_len(self, ctx):
        """Length of the key in bytes."""
        vscf_ed25519_private_key_key_len = self._lib.vscf_ed25519_private_key_key_len
        vscf_ed25519_private_key_key_len.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_key_len.restype = c_size_t
        return vscf_ed25519_private_key_key_len(ctx)

    def vscf_ed25519_private_key_key_bitlen(self, ctx):
        """Length of the key in bits."""
        vscf_ed25519_private_key_key_bitlen = self._lib.vscf_ed25519_private_key_key_bitlen
        vscf_ed25519_private_key_key_bitlen.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_key_bitlen.restype = c_size_t
        return vscf_ed25519_private_key_key_bitlen(ctx)

    def vscf_ed25519_private_key_generate_key(self, ctx):
        """Generate new private or secret key.
        Note, this operation can be slow."""
        vscf_ed25519_private_key_generate_key = self._lib.vscf_ed25519_private_key_generate_key
        vscf_ed25519_private_key_generate_key.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_generate_key.restype = c_int
        return vscf_ed25519_private_key_generate_key(ctx)

    def vscf_ed25519_private_key_decrypt(self, ctx, data, out):
        """Decrypt given data."""
        vscf_ed25519_private_key_decrypt = self._lib.vscf_ed25519_private_key_decrypt
        vscf_ed25519_private_key_decrypt.argtypes = [POINTER(vscf_ed25519_private_key_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_ed25519_private_key_decrypt.restype = c_int
        return vscf_ed25519_private_key_decrypt(ctx, data, out)

    def vscf_ed25519_private_key_decrypted_len(self, ctx, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_ed25519_private_key_decrypted_len = self._lib.vscf_ed25519_private_key_decrypted_len
        vscf_ed25519_private_key_decrypted_len.argtypes = [POINTER(vscf_ed25519_private_key_t), c_size_t]
        vscf_ed25519_private_key_decrypted_len.restype = c_size_t
        return vscf_ed25519_private_key_decrypted_len(ctx, data_len)

    def vscf_ed25519_private_key_signature_len(self, ctx):
        """Return length in bytes required to hold signature."""
        vscf_ed25519_private_key_signature_len = self._lib.vscf_ed25519_private_key_signature_len
        vscf_ed25519_private_key_signature_len.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_signature_len.restype = c_size_t
        return vscf_ed25519_private_key_signature_len(ctx)

    def vscf_ed25519_private_key_sign_hash(self, ctx, hash_digest, hash_id, signature):
        """Sign data given private key."""
        vscf_ed25519_private_key_sign_hash = self._lib.vscf_ed25519_private_key_sign_hash
        vscf_ed25519_private_key_sign_hash.argtypes = [POINTER(vscf_ed25519_private_key_t), vsc_data_t, c_int, POINTER(vsc_buffer_t)]
        vscf_ed25519_private_key_sign_hash.restype = c_int
        return vscf_ed25519_private_key_sign_hash(ctx, hash_digest, hash_id, signature)

    def vscf_ed25519_private_key_extract_public_key(self, ctx):
        """Extract public part of the key."""
        vscf_ed25519_private_key_extract_public_key = self._lib.vscf_ed25519_private_key_extract_public_key
        vscf_ed25519_private_key_extract_public_key.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_extract_public_key.restype = POINTER(vscf_impl_t)
        return vscf_ed25519_private_key_extract_public_key(ctx)

    def vscf_ed25519_private_key_export_private_key(self, ctx, out):
        """Export private key in the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_ed25519_private_key_export_private_key = self._lib.vscf_ed25519_private_key_export_private_key
        vscf_ed25519_private_key_export_private_key.argtypes = [POINTER(vscf_ed25519_private_key_t), POINTER(vsc_buffer_t)]
        vscf_ed25519_private_key_export_private_key.restype = c_int
        return vscf_ed25519_private_key_export_private_key(ctx, out)

    def vscf_ed25519_private_key_exported_private_key_len(self, ctx):
        """Return length in bytes required to hold exported private key."""
        vscf_ed25519_private_key_exported_private_key_len = self._lib.vscf_ed25519_private_key_exported_private_key_len
        vscf_ed25519_private_key_exported_private_key_len.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_exported_private_key_len.restype = c_size_t
        return vscf_ed25519_private_key_exported_private_key_len(ctx)

    def vscf_ed25519_private_key_import_private_key(self, ctx, data):
        """Import private key from the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_ed25519_private_key_import_private_key = self._lib.vscf_ed25519_private_key_import_private_key
        vscf_ed25519_private_key_import_private_key.argtypes = [POINTER(vscf_ed25519_private_key_t), vsc_data_t]
        vscf_ed25519_private_key_import_private_key.restype = c_int
        return vscf_ed25519_private_key_import_private_key(ctx, data)

    def vscf_ed25519_private_key_compute_shared_key(self, ctx, public_key, shared_key):
        """Compute shared key for 2 asymmetric keys.
        Note, shared key can be used only for symmetric cryptography."""
        vscf_ed25519_private_key_compute_shared_key = self._lib.vscf_ed25519_private_key_compute_shared_key
        vscf_ed25519_private_key_compute_shared_key.argtypes = [POINTER(vscf_ed25519_private_key_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_ed25519_private_key_compute_shared_key.restype = c_int
        return vscf_ed25519_private_key_compute_shared_key(ctx, public_key, shared_key)

    def vscf_ed25519_private_key_shared_key_len(self, ctx):
        """Return number of bytes required to hold shared key."""
        vscf_ed25519_private_key_shared_key_len = self._lib.vscf_ed25519_private_key_shared_key_len
        vscf_ed25519_private_key_shared_key_len.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_shared_key_len.restype = c_size_t
        return vscf_ed25519_private_key_shared_key_len(ctx)

    def vscf_ed25519_private_key_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_ed25519_private_key_setup_defaults = self._lib.vscf_ed25519_private_key_setup_defaults
        vscf_ed25519_private_key_setup_defaults.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_setup_defaults.restype = c_int
        return vscf_ed25519_private_key_setup_defaults(ctx)

    def vscf_ed25519_private_key_shallow_copy(self, ctx):
        vscf_ed25519_private_key_shallow_copy = self._lib.vscf_ed25519_private_key_shallow_copy
        vscf_ed25519_private_key_shallow_copy.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_shallow_copy.restype = POINTER(vscf_ed25519_private_key_t)
        return vscf_ed25519_private_key_shallow_copy(ctx)

    def vscf_ed25519_private_key_impl(self, ctx):
        vscf_ed25519_private_key_impl = self._lib.vscf_ed25519_private_key_impl
        vscf_ed25519_private_key_impl.argtypes = [POINTER(vscf_ed25519_private_key_t)]
        vscf_ed25519_private_key_impl.restype = POINTER(vscf_impl_t)
        return vscf_ed25519_private_key_impl(ctx)
