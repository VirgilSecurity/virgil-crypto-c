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
from ._c_bridge import VscfKeyMaterialRng
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from .random import Random


class KeyMaterialRng(Random):
    """Random number generator that generate deterministic sequence based
    on a given seed.
    This RNG can be used to transform key material rial to the private key."""

    # Minimum length in bytes for the key material.
    KEY_MATERIAL_LEN_MIN = 32
    # Maximum length in bytes for the key material.
    KEY_MATERIAL_LEN_MAX = 512

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_material_rng = VscfKeyMaterialRng()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_key_material_rng.vscf_key_material_rng_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_key_material_rng.vscf_key_material_rng_delete(self.ctx)

    def random(self, data_len):
        """Generate random bytes.
        All RNG implementations must be thread-safe."""
        data = Buffer(data_len)
        status = self._lib_vscf_key_material_rng.vscf_key_material_rng_random(self.ctx, data_len, data.c_buffer)
        VscfStatus.handle_status(status)
        return data.get_bytes()

    def reseed(self):
        """Retrieve new seed data from the entropy sources."""
        status = self._lib_vscf_key_material_rng.vscf_key_material_rng_reseed(self.ctx)
        VscfStatus.handle_status(status)

    def reset_key_material(self, key_material):
        """Set a new key material."""
        d_key_material = Data(key_material)
        self._lib_vscf_key_material_rng.vscf_key_material_rng_reset_key_material(self.ctx, d_key_material.data)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_material_rng = VscfKeyMaterialRng()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_material_rng = VscfKeyMaterialRng()
        inst.ctx = inst._lib_vscf_key_material_rng.vscf_key_material_rng_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_key_material_rng.vscf_key_material_rng_shallow_copy(value)
        self._c_impl = self._lib_vscf_key_material_rng.vscf_key_material_rng_impl(self.ctx)
