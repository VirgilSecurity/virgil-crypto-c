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
from ._vscf_error import vscf_error_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_key_provider_t(Structure):
    pass


class VscfKeyProvider(object):
    """Provide functionality for private key generation and importing that
    relies on the software default implementations."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_provider_new(self):
        vscf_key_provider_new = self._lib.vscf_key_provider_new
        vscf_key_provider_new.argtypes = []
        vscf_key_provider_new.restype = POINTER(vscf_key_provider_t)
        return vscf_key_provider_new()

    def vscf_key_provider_delete(self, ctx):
        vscf_key_provider_delete = self._lib.vscf_key_provider_delete
        vscf_key_provider_delete.argtypes = [POINTER(vscf_key_provider_t)]
        vscf_key_provider_delete.restype = None
        return vscf_key_provider_delete(ctx)

    def vscf_key_provider_use_random(self, ctx, random):
        vscf_key_provider_use_random = self._lib.vscf_key_provider_use_random
        vscf_key_provider_use_random.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_impl_t)]
        vscf_key_provider_use_random.restype = None
        return vscf_key_provider_use_random(ctx, random)

    def vscf_key_provider_use_ecies(self, ctx, ecies):
        vscf_key_provider_use_ecies = self._lib.vscf_key_provider_use_ecies
        vscf_key_provider_use_ecies.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_ecies_t)]
        vscf_key_provider_use_ecies.restype = None
        return vscf_key_provider_use_ecies(ctx, ecies)

    def vscf_key_provider_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_key_provider_setup_defaults = self._lib.vscf_key_provider_setup_defaults
        vscf_key_provider_setup_defaults.argtypes = [POINTER(vscf_key_provider_t)]
        vscf_key_provider_setup_defaults.restype = c_int
        return vscf_key_provider_setup_defaults(ctx)

    def vscf_key_provider_set_rsa_params(self, ctx, bitlen):
        """Setup parameters that is used during RSA key generation."""
        vscf_key_provider_set_rsa_params = self._lib.vscf_key_provider_set_rsa_params
        vscf_key_provider_set_rsa_params.argtypes = [POINTER(vscf_key_provider_t), c_size_t]
        vscf_key_provider_set_rsa_params.restype = None
        return vscf_key_provider_set_rsa_params(ctx, bitlen)

    def vscf_key_provider_generate_private_key(self, ctx, alg_id, error):
        """Generate new private key from the given id."""
        vscf_key_provider_generate_private_key = self._lib.vscf_key_provider_generate_private_key
        vscf_key_provider_generate_private_key.argtypes = [POINTER(vscf_key_provider_t), c_int, POINTER(vscf_error_t)]
        vscf_key_provider_generate_private_key.restype = POINTER(vscf_impl_t)
        return vscf_key_provider_generate_private_key(ctx, alg_id, error)

    def vscf_key_provider_import_private_key(self, ctx, key_data, error):
        """Import private key from the PKCS#8 format."""
        vscf_key_provider_import_private_key = self._lib.vscf_key_provider_import_private_key
        vscf_key_provider_import_private_key.argtypes = [POINTER(vscf_key_provider_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_key_provider_import_private_key.restype = POINTER(vscf_impl_t)
        return vscf_key_provider_import_private_key(ctx, key_data, error)

    def vscf_key_provider_import_public_key(self, ctx, key_data, error):
        """Import public key from the PKCS#8 format."""
        vscf_key_provider_import_public_key = self._lib.vscf_key_provider_import_public_key
        vscf_key_provider_import_public_key.argtypes = [POINTER(vscf_key_provider_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_key_provider_import_public_key.restype = POINTER(vscf_impl_t)
        return vscf_key_provider_import_public_key(ctx, key_data, error)

    def vscf_key_provider_exported_public_key_len(self, ctx, public_key):
        """Calculate buffer size enough to hold exported public key.

        Precondition: public key must be exportable."""
        vscf_key_provider_exported_public_key_len = self._lib.vscf_key_provider_exported_public_key_len
        vscf_key_provider_exported_public_key_len.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_impl_t)]
        vscf_key_provider_exported_public_key_len.restype = c_size_t
        return vscf_key_provider_exported_public_key_len(ctx, public_key)

    def vscf_key_provider_export_public_key(self, ctx, public_key, out):
        """Export given public key to the PKCS#8 DER format.

        Precondition: public key must be exportable."""
        vscf_key_provider_export_public_key = self._lib.vscf_key_provider_export_public_key
        vscf_key_provider_export_public_key.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_key_provider_export_public_key.restype = c_int
        return vscf_key_provider_export_public_key(ctx, public_key, out)

    def vscf_key_provider_exported_private_key_len(self, ctx, private_key):
        """Calculate buffer size enough to hold exported private key.

        Precondition: private key must be exportable."""
        vscf_key_provider_exported_private_key_len = self._lib.vscf_key_provider_exported_private_key_len
        vscf_key_provider_exported_private_key_len.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_impl_t)]
        vscf_key_provider_exported_private_key_len.restype = c_size_t
        return vscf_key_provider_exported_private_key_len(ctx, private_key)

    def vscf_key_provider_export_private_key(self, ctx, private_key, out):
        """Export given private key to the PKCS#8 or SEC1 DER format.

        Precondition: private key must be exportable."""
        vscf_key_provider_export_private_key = self._lib.vscf_key_provider_export_private_key
        vscf_key_provider_export_private_key.argtypes = [POINTER(vscf_key_provider_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_key_provider_export_private_key.restype = c_int
        return vscf_key_provider_export_private_key(ctx, private_key, out)

    def vscf_key_provider_shallow_copy(self, ctx):
        vscf_key_provider_shallow_copy = self._lib.vscf_key_provider_shallow_copy
        vscf_key_provider_shallow_copy.argtypes = [POINTER(vscf_key_provider_t)]
        vscf_key_provider_shallow_copy.restype = POINTER(vscf_key_provider_t)
        return vscf_key_provider_shallow_copy(ctx)
