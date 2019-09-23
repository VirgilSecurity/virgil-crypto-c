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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_ctr_drbg_t(Structure):
    pass


class VscfCtrDrbg(object):
    """Implementation of the RNG using deterministic random bit generators
    based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
    This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled."""

    # The interval before reseed is performed by default.
    RESEED_INTERVAL = 10000
    # The amount of entropy used per seed by default.
    ENTROPY_LEN = 48

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_ctr_drbg_new(self):
        vscf_ctr_drbg_new = self._lib.vscf_ctr_drbg_new
        vscf_ctr_drbg_new.argtypes = []
        vscf_ctr_drbg_new.restype = POINTER(vscf_ctr_drbg_t)
        return vscf_ctr_drbg_new()

    def vscf_ctr_drbg_delete(self, ctx):
        vscf_ctr_drbg_delete = self._lib.vscf_ctr_drbg_delete
        vscf_ctr_drbg_delete.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_delete.restype = None
        return vscf_ctr_drbg_delete(ctx)

    def vscf_ctr_drbg_use_entropy_source(self, ctx, entropy_source):
        vscf_ctr_drbg_use_entropy_source = self._lib.vscf_ctr_drbg_use_entropy_source
        vscf_ctr_drbg_use_entropy_source.argtypes = [POINTER(vscf_ctr_drbg_t), POINTER(vscf_impl_t)]
        vscf_ctr_drbg_use_entropy_source.restype = None
        return vscf_ctr_drbg_use_entropy_source(ctx, entropy_source)

    def vscf_ctr_drbg_random(self, ctx, data_len, data):
        """Generate random bytes.
        All RNG implementations must be thread-safe."""
        vscf_ctr_drbg_random = self._lib.vscf_ctr_drbg_random
        vscf_ctr_drbg_random.argtypes = [POINTER(vscf_ctr_drbg_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_ctr_drbg_random.restype = c_int
        return vscf_ctr_drbg_random(ctx, data_len, data)

    def vscf_ctr_drbg_reseed(self, ctx):
        """Retrieve new seed data from the entropy sources."""
        vscf_ctr_drbg_reseed = self._lib.vscf_ctr_drbg_reseed
        vscf_ctr_drbg_reseed.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_reseed.restype = c_int
        return vscf_ctr_drbg_reseed(ctx)

    def vscf_ctr_drbg_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_ctr_drbg_setup_defaults = self._lib.vscf_ctr_drbg_setup_defaults
        vscf_ctr_drbg_setup_defaults.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_setup_defaults.restype = c_int
        return vscf_ctr_drbg_setup_defaults(ctx)

    def vscf_ctr_drbg_enable_prediction_resistance(self, ctx):
        """Force entropy to be gathered at the beginning of every call to
        the random() method.
        Note, use this if your entropy source has sufficient throughput."""
        vscf_ctr_drbg_enable_prediction_resistance = self._lib.vscf_ctr_drbg_enable_prediction_resistance
        vscf_ctr_drbg_enable_prediction_resistance.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_enable_prediction_resistance.restype = None
        return vscf_ctr_drbg_enable_prediction_resistance(ctx)

    def vscf_ctr_drbg_set_reseed_interval(self, ctx, interval):
        """Sets the reseed interval.
        Default value is reseed interval."""
        vscf_ctr_drbg_set_reseed_interval = self._lib.vscf_ctr_drbg_set_reseed_interval
        vscf_ctr_drbg_set_reseed_interval.argtypes = [POINTER(vscf_ctr_drbg_t), c_size_t]
        vscf_ctr_drbg_set_reseed_interval.restype = None
        return vscf_ctr_drbg_set_reseed_interval(ctx, interval)

    def vscf_ctr_drbg_set_entropy_len(self, ctx, len):
        """Sets the amount of entropy grabbed on each seed or reseed.
        The default value is entropy len."""
        vscf_ctr_drbg_set_entropy_len = self._lib.vscf_ctr_drbg_set_entropy_len
        vscf_ctr_drbg_set_entropy_len.argtypes = [POINTER(vscf_ctr_drbg_t), c_size_t]
        vscf_ctr_drbg_set_entropy_len.restype = None
        return vscf_ctr_drbg_set_entropy_len(ctx, len)

    def vscf_ctr_drbg_shallow_copy(self, ctx):
        vscf_ctr_drbg_shallow_copy = self._lib.vscf_ctr_drbg_shallow_copy
        vscf_ctr_drbg_shallow_copy.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_shallow_copy.restype = POINTER(vscf_ctr_drbg_t)
        return vscf_ctr_drbg_shallow_copy(ctx)

    def vscf_ctr_drbg_impl(self, ctx):
        vscf_ctr_drbg_impl = self._lib.vscf_ctr_drbg_impl
        vscf_ctr_drbg_impl.argtypes = [POINTER(vscf_ctr_drbg_t)]
        vscf_ctr_drbg_impl.restype = POINTER(vscf_impl_t)
        return vscf_ctr_drbg_impl(ctx)
