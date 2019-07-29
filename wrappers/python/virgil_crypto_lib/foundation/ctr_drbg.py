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
from ._c_bridge import VscfCtrDrbg
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from .random import Random


class CtrDrbg(Random):
    """Implementation of the RNG using deterministic random bit generators
    based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
    This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled."""

    # The interval before reseed is performed by default.
    RESEED_INTERVAL = 10000
    # The amount of entropy used per seed by default.
    ENTROPY_LEN = 48

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_ctr_drbg = VscfCtrDrbg()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_ctr_drbg.vscf_ctr_drbg_delete(self.ctx)

    def set_entropy_source(self, entropy_source):
        self._lib_vscf_ctr_drbg.vscf_ctr_drbg_use_entropy_source(self.ctx, entropy_source.c_impl)

    def random(self, data_len):
        """Generate random bytes.
        All RNG implementations must be thread-safe."""
        data = Buffer(data_len)
        status = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_random(self.ctx, data_len, data.c_buffer)
        VscfStatus.handle_status(status)
        return data.get_bytes()

    def reseed(self):
        """Retrieve new seed data from the entropy sources."""
        status = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_reseed(self.ctx)
        VscfStatus.handle_status(status)

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        status = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def enable_prediction_resistance(self):
        """Force entropy to be gathered at the beginning of every call to
        the random() method.
        Note, use this if your entropy source has sufficient throughput."""
        self._lib_vscf_ctr_drbg.vscf_ctr_drbg_enable_prediction_resistance(self.ctx)

    def set_reseed_interval(self, interval):
        """Sets the reseed interval.
        Default value is reseed interval."""
        self._lib_vscf_ctr_drbg.vscf_ctr_drbg_set_reseed_interval(self.ctx, interval)

    def set_entropy_len(self, len):
        """Sets the amount of entropy grabbed on each seed or reseed.
        The default value is entropy len."""
        self._lib_vscf_ctr_drbg.vscf_ctr_drbg_set_entropy_len(self.ctx, len)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ctr_drbg = VscfCtrDrbg()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ctr_drbg = VscfCtrDrbg()
        inst.ctx = inst._lib_vscf_ctr_drbg.vscf_ctr_drbg_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_shallow_copy(value)
        self._c_impl = self._lib_vscf_ctr_drbg.vscf_ctr_drbg_impl(self.ctx)
