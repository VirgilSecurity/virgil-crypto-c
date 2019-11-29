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


class vscf_seed_entropy_source_t(Structure):
    pass


class VscfSeedEntropySource(object):
    """Deterministic entropy source that is based only on the given seed."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_seed_entropy_source_new(self):
        vscf_seed_entropy_source_new = self._lib.vscf_seed_entropy_source_new
        vscf_seed_entropy_source_new.argtypes = []
        vscf_seed_entropy_source_new.restype = POINTER(vscf_seed_entropy_source_t)
        return vscf_seed_entropy_source_new()

    def vscf_seed_entropy_source_delete(self, ctx):
        vscf_seed_entropy_source_delete = self._lib.vscf_seed_entropy_source_delete
        vscf_seed_entropy_source_delete.argtypes = [POINTER(vscf_seed_entropy_source_t)]
        vscf_seed_entropy_source_delete.restype = None
        return vscf_seed_entropy_source_delete(ctx)

    def vscf_seed_entropy_source_is_strong(self, ctx):
        """Defines that implemented source is strong."""
        vscf_seed_entropy_source_is_strong = self._lib.vscf_seed_entropy_source_is_strong
        vscf_seed_entropy_source_is_strong.argtypes = [POINTER(vscf_seed_entropy_source_t)]
        vscf_seed_entropy_source_is_strong.restype = c_bool
        return vscf_seed_entropy_source_is_strong(ctx)

    def vscf_seed_entropy_source_gather(self, ctx, len, out):
        """Gather entropy of the requested length."""
        vscf_seed_entropy_source_gather = self._lib.vscf_seed_entropy_source_gather
        vscf_seed_entropy_source_gather.argtypes = [POINTER(vscf_seed_entropy_source_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_seed_entropy_source_gather.restype = c_int
        return vscf_seed_entropy_source_gather(ctx, len, out)

    def vscf_seed_entropy_source_reset_seed(self, ctx, seed):
        """Set a new seed as an entropy source."""
        vscf_seed_entropy_source_reset_seed = self._lib.vscf_seed_entropy_source_reset_seed
        vscf_seed_entropy_source_reset_seed.argtypes = [POINTER(vscf_seed_entropy_source_t), vsc_data_t]
        vscf_seed_entropy_source_reset_seed.restype = None
        return vscf_seed_entropy_source_reset_seed(ctx, seed)

    def vscf_seed_entropy_source_shallow_copy(self, ctx):
        vscf_seed_entropy_source_shallow_copy = self._lib.vscf_seed_entropy_source_shallow_copy
        vscf_seed_entropy_source_shallow_copy.argtypes = [POINTER(vscf_seed_entropy_source_t)]
        vscf_seed_entropy_source_shallow_copy.restype = POINTER(vscf_seed_entropy_source_t)
        return vscf_seed_entropy_source_shallow_copy(ctx)

    def vscf_seed_entropy_source_impl(self, ctx):
        vscf_seed_entropy_source_impl = self._lib.vscf_seed_entropy_source_impl
        vscf_seed_entropy_source_impl.argtypes = [POINTER(vscf_seed_entropy_source_t)]
        vscf_seed_entropy_source_impl.restype = POINTER(vscf_impl_t)
        return vscf_seed_entropy_source_impl(ctx)
