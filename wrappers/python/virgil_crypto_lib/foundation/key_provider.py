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
from ._c_bridge import VscfKeyProvider
from ._c_bridge import VscfStatus
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfImplTag
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class KeyProvider(object):
    """Provide functionality for private key generation and importing that
    relies on the software default implementations."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_provider = VscfKeyProvider()
        self.ctx = self._lib_vscf_key_provider.vscf_key_provider_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_key_provider.vscf_key_provider_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_key_provider.vscf_key_provider_use_random(self.ctx, random.c_impl)

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_key_provider.vscf_key_provider_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def set_rsa_params(self, bitlen):
        """Setup parameters that is used during RSA key generation."""
        self._lib_vscf_key_provider.vscf_key_provider_set_rsa_params(self.ctx, bitlen)

    def generate_private_key(self, alg_id):
        """Generate new private key with a given algorithm."""
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_generate_private_key(self.ctx, alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def generate_post_quantum_private_key(self):
        """Generate new post-quantum private key with default algorithms.
        Note, that a post-quantum key combines classic private keys
        alongside with post-quantum private keys.
        Current structure is "compound private key" is:
            - cipher private key is "hybrid private key" where:
                - first key is a classic private key;
                - second key is a post-quantum private key;
            - signer private key "hybrid private key" where:
                - first key is a classic private key;
                - second key is a post-quantum private key."""
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_generate_post_quantum_private_key(self.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def generate_compound_private_key(self, cipher_alg_id, signer_alg_id):
        """Generate new compound private key with given algorithms."""
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_generate_compound_private_key(self.ctx, cipher_alg_id, signer_alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def generate_hybrid_private_key(self, first_key_alg_id, second_key_alg_id):
        """Generate new hybrid private key with given algorithms."""
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_generate_hybrid_private_key(self.ctx, first_key_alg_id, second_key_alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def generate_compound_hybrid_private_key(self, cipher_first_key_alg_id, cipher_second_key_alg_id, signer_first_key_alg_id, signer_second_key_alg_id):
        """Generate new compound private key with nested hybrid private keys.

        Note, second key algorithm identifiers can be NONE, in this case,
        a regular key will be crated instead of a hybrid key."""
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_generate_compound_hybrid_private_key(self.ctx, cipher_first_key_alg_id, cipher_second_key_alg_id, signer_first_key_alg_id, signer_second_key_alg_id, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_private_key(self, key_data):
        """Import private key from the PKCS#8 format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_import_private_key(self.ctx, d_key_data.data, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def import_public_key(self, key_data):
        """Import public key from the PKCS#8 format."""
        d_key_data = Data(key_data)
        error = vscf_error_t()
        result = self._lib_vscf_key_provider.vscf_key_provider_import_public_key(self.ctx, d_key_data.data, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def exported_public_key_len(self, public_key):
        """Calculate buffer size enough to hold exported public key.

        Precondition: public key must be exportable."""
        result = self._lib_vscf_key_provider.vscf_key_provider_exported_public_key_len(self.ctx, public_key.c_impl)
        return result

    def export_public_key(self, public_key):
        """Export given public key to the PKCS#8 DER format.

        Precondition: public key must be exportable."""
        out = Buffer(self.exported_public_key_len(public_key=public_key))
        status = self._lib_vscf_key_provider.vscf_key_provider_export_public_key(self.ctx, public_key.c_impl, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def exported_private_key_len(self, private_key):
        """Calculate buffer size enough to hold exported private key.

        Precondition: private key must be exportable."""
        result = self._lib_vscf_key_provider.vscf_key_provider_exported_private_key_len(self.ctx, private_key.c_impl)
        return result

    def export_private_key(self, private_key):
        """Export given private key to the PKCS#8 or SEC1 DER format.

        Precondition: private key must be exportable."""
        out = Buffer(self.exported_private_key_len(private_key=private_key))
        status = self._lib_vscf_key_provider.vscf_key_provider_export_private_key(self.ctx, private_key.c_impl, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_provider = VscfKeyProvider()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_provider = VscfKeyProvider()
        inst.ctx = inst._lib_vscf_key_provider.vscf_key_provider_shallow_copy(c_ctx)
        return inst
