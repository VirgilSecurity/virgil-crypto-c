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


class vscf_round5_t(Structure):
    pass


class VscfRound5(object):
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
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_round5_new(self):
        vscf_round5_new = self._lib.vscf_round5_new
        vscf_round5_new.argtypes = []
        vscf_round5_new.restype = POINTER(vscf_round5_t)
        return vscf_round5_new()

    def vscf_round5_delete(self, ctx):
        vscf_round5_delete = self._lib.vscf_round5_delete
        vscf_round5_delete.argtypes = [POINTER(vscf_round5_t)]
        vscf_round5_delete.restype = None
        return vscf_round5_delete(ctx)

    def vscf_round5_use_random(self, ctx, random):
        vscf_round5_use_random = self._lib.vscf_round5_use_random
        vscf_round5_use_random.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t)]
        vscf_round5_use_random.restype = None
        return vscf_round5_use_random(ctx, random)

    def vscf_round5_generate_ephemeral_key(self, ctx, key, error):
        """Generate ephemeral private key of the same type.
        Note, this operation might be slow."""
        vscf_round5_generate_ephemeral_key = self._lib.vscf_round5_generate_ephemeral_key
        vscf_round5_generate_ephemeral_key.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_round5_generate_ephemeral_key.restype = POINTER(vscf_impl_t)
        return vscf_round5_generate_ephemeral_key(ctx, key, error)

    def vscf_round5_import_public_key(self, ctx, raw_key, error):
        """Import public key from the raw binary format.

        Return public key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be imported from the format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_round5_import_public_key = self._lib.vscf_round5_import_public_key
        vscf_round5_import_public_key.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_raw_public_key_t), POINTER(vscf_error_t)]
        vscf_round5_import_public_key.restype = POINTER(vscf_impl_t)
        return vscf_round5_import_public_key(ctx, raw_key, error)

    def vscf_round5_import_public_key_data(self, ctx, key_data, key_alg_info, error):
        """Import public key from the raw binary format."""
        vscf_round5_import_public_key_data = self._lib.vscf_round5_import_public_key_data
        vscf_round5_import_public_key_data.argtypes = [POINTER(vscf_round5_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_round5_import_public_key_data.restype = POINTER(vscf_impl_t)
        return vscf_round5_import_public_key_data(ctx, key_data, key_alg_info, error)

    def vscf_round5_export_public_key(self, ctx, public_key, error):
        """Export public key to the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_round5_export_public_key = self._lib.vscf_round5_export_public_key
        vscf_round5_export_public_key.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_round5_export_public_key.restype = POINTER(vscf_raw_public_key_t)
        return vscf_round5_export_public_key(ctx, public_key, error)

    def vscf_round5_exported_public_key_data_len(self, ctx, public_key):
        """Return length in bytes required to hold exported public key."""
        vscf_round5_exported_public_key_data_len = self._lib.vscf_round5_exported_public_key_data_len
        vscf_round5_exported_public_key_data_len.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t)]
        vscf_round5_exported_public_key_data_len.restype = c_size_t
        return vscf_round5_exported_public_key_data_len(ctx, public_key)

    def vscf_round5_export_public_key_data(self, ctx, public_key, out):
        """Export public key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA public key must be exported in format defined in
        RFC 3447 Appendix A.1.1."""
        vscf_round5_export_public_key_data = self._lib.vscf_round5_export_public_key_data
        vscf_round5_export_public_key_data.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_round5_export_public_key_data.restype = c_int
        return vscf_round5_export_public_key_data(ctx, public_key, out)

    def vscf_round5_import_private_key(self, ctx, raw_key, error):
        """Import private key from the raw binary format.

        Return private key that is adopted and optimized to be used
        with this particular algorithm.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_round5_import_private_key = self._lib.vscf_round5_import_private_key
        vscf_round5_import_private_key.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_raw_private_key_t), POINTER(vscf_error_t)]
        vscf_round5_import_private_key.restype = POINTER(vscf_impl_t)
        return vscf_round5_import_private_key(ctx, raw_key, error)

    def vscf_round5_import_private_key_data(self, ctx, key_data, key_alg_info, error):
        """Import private key from the raw binary format."""
        vscf_round5_import_private_key_data = self._lib.vscf_round5_import_private_key_data
        vscf_round5_import_private_key_data.argtypes = [POINTER(vscf_round5_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_round5_import_private_key_data.restype = POINTER(vscf_impl_t)
        return vscf_round5_import_private_key_data(ctx, key_data, key_alg_info, error)

    def vscf_round5_export_private_key(self, ctx, private_key, error):
        """Export private key in the raw binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_round5_export_private_key = self._lib.vscf_round5_export_private_key
        vscf_round5_export_private_key.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_round5_export_private_key.restype = POINTER(vscf_raw_private_key_t)
        return vscf_round5_export_private_key(ctx, private_key, error)

    def vscf_round5_exported_private_key_data_len(self, ctx, private_key):
        """Return length in bytes required to hold exported private key."""
        vscf_round5_exported_private_key_data_len = self._lib.vscf_round5_exported_private_key_data_len
        vscf_round5_exported_private_key_data_len.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t)]
        vscf_round5_exported_private_key_data_len.restype = c_size_t
        return vscf_round5_exported_private_key_data_len(ctx, private_key)

    def vscf_round5_export_private_key_data(self, ctx, private_key, out):
        """Export private key to the raw binary format without algorithm information.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        vscf_round5_export_private_key_data = self._lib.vscf_round5_export_private_key_data
        vscf_round5_export_private_key_data.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_round5_export_private_key_data.restype = c_int
        return vscf_round5_export_private_key_data(ctx, private_key, out)

    def vscf_round5_kem_shared_key_len(self, ctx, key):
        """Return length in bytes required to hold encapsulated shared key."""
        vscf_round5_kem_shared_key_len = self._lib.vscf_round5_kem_shared_key_len
        vscf_round5_kem_shared_key_len.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t)]
        vscf_round5_kem_shared_key_len.restype = c_size_t
        return vscf_round5_kem_shared_key_len(ctx, key)

    def vscf_round5_kem_encapsulated_key_len(self, ctx, public_key):
        """Return length in bytes required to hold encapsulated key."""
        vscf_round5_kem_encapsulated_key_len = self._lib.vscf_round5_kem_encapsulated_key_len
        vscf_round5_kem_encapsulated_key_len.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t)]
        vscf_round5_kem_encapsulated_key_len.restype = c_size_t
        return vscf_round5_kem_encapsulated_key_len(ctx, public_key)

    def vscf_round5_kem_encapsulate(self, ctx, public_key, shared_key, encapsulated_key):
        """Generate a shared key and a key encapsulated message."""
        vscf_round5_kem_encapsulate = self._lib.vscf_round5_kem_encapsulate
        vscf_round5_kem_encapsulate.argtypes = [POINTER(vscf_round5_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscf_round5_kem_encapsulate.restype = c_int
        return vscf_round5_kem_encapsulate(ctx, public_key, shared_key, encapsulated_key)

    def vscf_round5_kem_decapsulate(self, ctx, encapsulated_key, private_key, shared_key):
        """Decapsulate the shared key."""
        vscf_round5_kem_decapsulate = self._lib.vscf_round5_kem_decapsulate
        vscf_round5_kem_decapsulate.argtypes = [POINTER(vscf_round5_t), vsc_data_t, POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_round5_kem_decapsulate.restype = c_int
        return vscf_round5_kem_decapsulate(ctx, encapsulated_key, private_key, shared_key)

    def vscf_round5_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_round5_setup_defaults = self._lib.vscf_round5_setup_defaults
        vscf_round5_setup_defaults.argtypes = [POINTER(vscf_round5_t)]
        vscf_round5_setup_defaults.restype = c_int
        return vscf_round5_setup_defaults(ctx)

    def vscf_round5_generate_key(self, ctx, alg_id, error):
        """Generate new private key.
        Note, this operation might be slow."""
        vscf_round5_generate_key = self._lib.vscf_round5_generate_key
        vscf_round5_generate_key.argtypes = [POINTER(vscf_round5_t), c_int, POINTER(vscf_error_t)]
        vscf_round5_generate_key.restype = POINTER(vscf_impl_t)
        return vscf_round5_generate_key(ctx, alg_id, error)

    def vscf_round5_shallow_copy(self, ctx):
        vscf_round5_shallow_copy = self._lib.vscf_round5_shallow_copy
        vscf_round5_shallow_copy.argtypes = [POINTER(vscf_round5_t)]
        vscf_round5_shallow_copy.restype = POINTER(vscf_round5_t)
        return vscf_round5_shallow_copy(ctx)

    def vscf_round5_impl(self, ctx):
        vscf_round5_impl = self._lib.vscf_round5_impl
        vscf_round5_impl.argtypes = [POINTER(vscf_round5_t)]
        vscf_round5_impl.restype = POINTER(vscf_impl_t)
        return vscf_round5_impl(ctx)
