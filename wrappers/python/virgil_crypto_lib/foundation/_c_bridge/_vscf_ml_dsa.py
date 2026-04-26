# Copyright (C) 2015-2026 Virgil Security, Inc.
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
from ._vscf_error import vscf_error_t
from ._vscf_raw_private_key import vscf_raw_private_key_t
from ._vscf_raw_public_key import vscf_raw_public_key_t


class vscf_ml_dsa_t(Structure):
    pass


class VscfMlDsa(object):
    """Provide post-quantum signature based on ML-DSA-65 (mldsa-native).
For algorithm details check https://github.com/pq-code-package/mldsa-native"""

    SEED_LEN = 32
    PUBLIC_KEY_LEN = 1952
    SECRET_KEY_LEN = 4032
    SIGNATURE_LEN = 3309

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_ml_dsa_new(self):
        vscf_ml_dsa_new = self._lib.vscf_ml_dsa_new
        vscf_ml_dsa_new.argtypes = []
        vscf_ml_dsa_new.restype = POINTER(vscf_ml_dsa_t)
        return vscf_ml_dsa_new()

    def vscf_ml_dsa_delete(self, ctx):
        vscf_ml_dsa_delete = self._lib.vscf_ml_dsa_delete
        vscf_ml_dsa_delete.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_delete.restype = None
        return vscf_ml_dsa_delete(ctx)

    def vscf_ml_dsa_use_random(self, ctx, random):
        vscf_ml_dsa_use_random = self._lib.vscf_ml_dsa_use_random
        vscf_ml_dsa_use_random.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t)]
        vscf_ml_dsa_use_random.restype = None
        return vscf_ml_dsa_use_random(ctx, random)

    def vscf_ml_dsa_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_ml_dsa_setup_defaults = self._lib.vscf_ml_dsa_setup_defaults
        vscf_ml_dsa_setup_defaults.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_setup_defaults.restype = c_int
        return vscf_ml_dsa_setup_defaults(ctx)

    def vscf_ml_dsa_generate_key(self, ctx, error):
        """Generate new private key.
Note, this operation might be slow."""
        vscf_ml_dsa_generate_key = self._lib.vscf_ml_dsa_generate_key
        vscf_ml_dsa_generate_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_generate_key.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_generate_key(ctx, error)

    def vscf_ml_dsa_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_ml_dsa_alg_id = self._lib.vscf_ml_dsa_alg_id
        vscf_ml_dsa_alg_id.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_alg_id.restype = c_int
        return vscf_ml_dsa_alg_id(ctx)

    def vscf_ml_dsa_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_ml_dsa_produce_alg_info = self._lib.vscf_ml_dsa_produce_alg_info
        vscf_ml_dsa_produce_alg_info.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_produce_alg_info(ctx)

    def vscf_ml_dsa_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_ml_dsa_restore_alg_info = self._lib.vscf_ml_dsa_restore_alg_info
        vscf_ml_dsa_restore_alg_info.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t)]
        vscf_ml_dsa_restore_alg_info.restype = c_int
        return vscf_ml_dsa_restore_alg_info(ctx, alg_info)

    def vscf_ml_dsa_generate_ephemeral_key(self, ctx, key, error):
        """Generate ephemeral private key of the same type.
Note, this operation might be slow."""
        vscf_ml_dsa_generate_ephemeral_key = self._lib.vscf_ml_dsa_generate_ephemeral_key
        vscf_ml_dsa_generate_ephemeral_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_generate_ephemeral_key.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_generate_ephemeral_key(ctx, key, error)

    def vscf_ml_dsa_import_public_key(self, ctx, raw_key, error):
        """Import public key from the raw binary format.

Return public key that is adopted and optimized to be used
with this particular algorithm.

Binary format must be defined in the key specification.
For instance, RSA public key must be imported from the format defined in
RFC 3447 Appendix A.1.1."""
        vscf_ml_dsa_import_public_key = self._lib.vscf_ml_dsa_import_public_key
        vscf_ml_dsa_import_public_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_raw_public_key_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_import_public_key.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_import_public_key(ctx, raw_key, error)

    def vscf_ml_dsa_export_public_key(self, ctx, public_key, error):
        """Export public key to the raw binary format.

Binary format must be defined in the key specification.
For instance, RSA public key must be exported in format defined in
RFC 3447 Appendix A.1.1."""
        vscf_ml_dsa_export_public_key = self._lib.vscf_ml_dsa_export_public_key
        vscf_ml_dsa_export_public_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_export_public_key.restype = POINTER(vscf_raw_public_key_t)
        return vscf_ml_dsa_export_public_key(ctx, public_key, error)

    def vscf_ml_dsa_import_private_key(self, ctx, raw_key, error):
        """Import private key from the raw binary format.

Return private key that is adopted and optimized to be used
with this particular algorithm.

Binary format must be defined in the key specification.
For instance, RSA private key must be imported from the format defined in
RFC 3447 Appendix A.1.2."""
        vscf_ml_dsa_import_private_key = self._lib.vscf_ml_dsa_import_private_key
        vscf_ml_dsa_import_private_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_raw_private_key_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_import_private_key.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_import_private_key(ctx, raw_key, error)

    def vscf_ml_dsa_export_private_key(self, ctx, private_key, error):
        """Export private key in the raw binary format.

Binary format must be defined in the key specification.
For instance, RSA private key must be exported in format defined in
RFC 3447 Appendix A.1.2."""
        vscf_ml_dsa_export_private_key = self._lib.vscf_ml_dsa_export_private_key
        vscf_ml_dsa_export_private_key.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_ml_dsa_export_private_key.restype = POINTER(vscf_raw_private_key_t)
        return vscf_ml_dsa_export_private_key(ctx, private_key, error)

    def vscf_ml_dsa_can_sign(self, ctx, private_key):
        """Check if algorithm can sign data digest with a given key."""
        vscf_ml_dsa_can_sign = self._lib.vscf_ml_dsa_can_sign
        vscf_ml_dsa_can_sign.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t)]
        vscf_ml_dsa_can_sign.restype = c_bool
        return vscf_ml_dsa_can_sign(ctx, private_key)

    def vscf_ml_dsa_signature_len(self, ctx, private_key):
        """Return length in bytes required to hold signature.
Return zero if a given private key can not produce signatures."""
        vscf_ml_dsa_signature_len = self._lib.vscf_ml_dsa_signature_len
        vscf_ml_dsa_signature_len.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t)]
        vscf_ml_dsa_signature_len.restype = c_size_t
        return vscf_ml_dsa_signature_len(ctx, private_key)

    def vscf_ml_dsa_sign_hash(self, ctx, private_key, hash_id, digest, signature):
        """Sign data digest with a given private key."""
        vscf_ml_dsa_sign_hash = self._lib.vscf_ml_dsa_sign_hash
        vscf_ml_dsa_sign_hash.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t), c_int, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_ml_dsa_sign_hash.restype = c_int
        return vscf_ml_dsa_sign_hash(ctx, private_key, hash_id, digest, signature)

    def vscf_ml_dsa_can_verify(self, ctx, public_key):
        """Check if algorithm can verify data digest with a given key."""
        vscf_ml_dsa_can_verify = self._lib.vscf_ml_dsa_can_verify
        vscf_ml_dsa_can_verify.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t)]
        vscf_ml_dsa_can_verify.restype = c_bool
        return vscf_ml_dsa_can_verify(ctx, public_key)

    def vscf_ml_dsa_verify_hash(self, ctx, public_key, hash_id, digest, signature):
        """Verify data digest with a given public key and signature."""
        vscf_ml_dsa_verify_hash = self._lib.vscf_ml_dsa_verify_hash
        vscf_ml_dsa_verify_hash.argtypes = [POINTER(vscf_ml_dsa_t), POINTER(vscf_impl_t), c_int, vsc_data_t, vsc_data_t]
        vscf_ml_dsa_verify_hash.restype = c_bool
        return vscf_ml_dsa_verify_hash(ctx, public_key, hash_id, digest, signature)

    def vscf_ml_dsa_shallow_copy(self, ctx):
        vscf_ml_dsa_shallow_copy = self._lib.vscf_ml_dsa_shallow_copy
        vscf_ml_dsa_shallow_copy.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_shallow_copy.restype = POINTER(vscf_ml_dsa_t)
        return vscf_ml_dsa_shallow_copy(ctx)

    def vscf_ml_dsa_impl(self, ctx):
        vscf_ml_dsa_impl = self._lib.vscf_ml_dsa_impl
        vscf_ml_dsa_impl.argtypes = [POINTER(vscf_ml_dsa_t)]
        vscf_ml_dsa_impl.restype = POINTER(vscf_impl_t)
        return vscf_ml_dsa_impl(ctx)
