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


class vscf_fake_random_t(Structure):
    pass


class VscfFakeRandom(object):
    """Random number generator that is used for test purposes only."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_fake_random_new(self):
        vscf_fake_random_new = self._lib.vscf_fake_random_new
        vscf_fake_random_new.argtypes = []
        vscf_fake_random_new.restype = POINTER(vscf_fake_random_t)
        return vscf_fake_random_new()

    def vscf_fake_random_delete(self, ctx):
        vscf_fake_random_delete = self._lib.vscf_fake_random_delete
        vscf_fake_random_delete.argtypes = [POINTER(vscf_fake_random_t)]
        vscf_fake_random_delete.restype = None
        return vscf_fake_random_delete(ctx)

    def vscf_fake_random_random(self, ctx, data_len, data):
        """Generate random bytes.
        All RNG implementations must be thread-safe."""
        vscf_fake_random_random = self._lib.vscf_fake_random_random
        vscf_fake_random_random.argtypes = [POINTER(vscf_fake_random_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_fake_random_random.restype = c_int
        return vscf_fake_random_random(ctx, data_len, data)

    def vscf_fake_random_reseed(self, ctx):
        """Retrieve new seed data from the entropy sources."""
        vscf_fake_random_reseed = self._lib.vscf_fake_random_reseed
        vscf_fake_random_reseed.argtypes = [POINTER(vscf_fake_random_t)]
        vscf_fake_random_reseed.restype = c_int
        return vscf_fake_random_reseed(ctx)

    def vscf_fake_random_is_strong(self, ctx):
        """Defines that implemented source is strong."""
        vscf_fake_random_is_strong = self._lib.vscf_fake_random_is_strong
        vscf_fake_random_is_strong.argtypes = [POINTER(vscf_fake_random_t)]
        vscf_fake_random_is_strong.restype = c_bool
        return vscf_fake_random_is_strong(ctx)

    def vscf_fake_random_gather(self, ctx, len, out):
        """Gather entropy of the requested length."""
        vscf_fake_random_gather = self._lib.vscf_fake_random_gather
        vscf_fake_random_gather.argtypes = [POINTER(vscf_fake_random_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_fake_random_gather.restype = c_int
        return vscf_fake_random_gather(ctx, len, out)

    def vscf_fake_random_setup_source_byte(self, ctx, byte_source):
        """Configure random number generator to generate sequence filled with given byte."""
        vscf_fake_random_setup_source_byte = self._lib.vscf_fake_random_setup_source_byte
        vscf_fake_random_setup_source_byte.argtypes = [POINTER(vscf_fake_random_t), c_byte]
        vscf_fake_random_setup_source_byte.restype = None
        return vscf_fake_random_setup_source_byte(ctx, byte_source)

    def vscf_fake_random_setup_source_data(self, ctx, data_source):
        """Configure random number generator to generate random sequence from given data.
        Note, that given data is used as circular source."""
        vscf_fake_random_setup_source_data = self._lib.vscf_fake_random_setup_source_data
        vscf_fake_random_setup_source_data.argtypes = [POINTER(vscf_fake_random_t), vsc_data_t]
        vscf_fake_random_setup_source_data.restype = None
        return vscf_fake_random_setup_source_data(ctx, data_source)

    def vscf_fake_random_shallow_copy(self, ctx):
        vscf_fake_random_shallow_copy = self._lib.vscf_fake_random_shallow_copy
        vscf_fake_random_shallow_copy.argtypes = [POINTER(vscf_fake_random_t)]
        vscf_fake_random_shallow_copy.restype = POINTER(vscf_fake_random_t)
        return vscf_fake_random_shallow_copy(ctx)

    def vscf_fake_random_impl(self, ctx):
        vscf_fake_random_impl = self._lib.vscf_fake_random_impl
        vscf_fake_random_impl.argtypes = [POINTER(vscf_fake_random_t)]
        vscf_fake_random_impl.restype = POINTER(vscf_impl_t)
        return vscf_fake_random_impl(ctx)
