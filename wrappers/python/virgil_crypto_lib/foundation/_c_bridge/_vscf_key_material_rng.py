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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_key_material_rng_t(Structure):
    pass


class VscfKeyMaterialRng(object):
    """Random number generator that generate deterministic sequence based
    on a given seed.
    This RNG can be used to transform key material rial to the private key."""

    # Minimum length in bytes for the key material.
    KEY_MATERIAL_LEN_MIN = 32
    # Maximum length in bytes for the key material.
    KEY_MATERIAL_LEN_MAX = 512

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_material_rng_new(self):
        vscf_key_material_rng_new = self._lib.vscf_key_material_rng_new
        vscf_key_material_rng_new.argtypes = []
        vscf_key_material_rng_new.restype = POINTER(vscf_key_material_rng_t)
        return vscf_key_material_rng_new()

    def vscf_key_material_rng_delete(self, ctx):
        vscf_key_material_rng_delete = self._lib.vscf_key_material_rng_delete
        vscf_key_material_rng_delete.argtypes = [POINTER(vscf_key_material_rng_t)]
        vscf_key_material_rng_delete.restype = None
        return vscf_key_material_rng_delete(ctx)

    def vscf_key_material_rng_random(self, ctx, data_len, data):
        """Generate random bytes.
        All RNG implementations must be thread-safe."""
        vscf_key_material_rng_random = self._lib.vscf_key_material_rng_random
        vscf_key_material_rng_random.argtypes = [POINTER(vscf_key_material_rng_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_key_material_rng_random.restype = c_int
        return vscf_key_material_rng_random(ctx, data_len, data)

    def vscf_key_material_rng_reseed(self, ctx):
        """Retrieve new seed data from the entropy sources."""
        vscf_key_material_rng_reseed = self._lib.vscf_key_material_rng_reseed
        vscf_key_material_rng_reseed.argtypes = [POINTER(vscf_key_material_rng_t)]
        vscf_key_material_rng_reseed.restype = c_int
        return vscf_key_material_rng_reseed(ctx)

    def vscf_key_material_rng_reset_key_material(self, ctx, key_material):
        """Set a new key material."""
        vscf_key_material_rng_reset_key_material = self._lib.vscf_key_material_rng_reset_key_material
        vscf_key_material_rng_reset_key_material.argtypes = [POINTER(vscf_key_material_rng_t), vsc_data_t]
        vscf_key_material_rng_reset_key_material.restype = None
        return vscf_key_material_rng_reset_key_material(ctx, key_material)

    def vscf_key_material_rng_shallow_copy(self, ctx):
        vscf_key_material_rng_shallow_copy = self._lib.vscf_key_material_rng_shallow_copy
        vscf_key_material_rng_shallow_copy.argtypes = [POINTER(vscf_key_material_rng_t)]
        vscf_key_material_rng_shallow_copy.restype = POINTER(vscf_key_material_rng_t)
        return vscf_key_material_rng_shallow_copy(ctx)

    def vscf_key_material_rng_impl(self, ctx):
        vscf_key_material_rng_impl = self._lib.vscf_key_material_rng_impl
        vscf_key_material_rng_impl.argtypes = [POINTER(vscf_key_material_rng_t)]
        vscf_key_material_rng_impl.restype = POINTER(vscf_impl_t)
        return vscf_key_material_rng_impl(ctx)
