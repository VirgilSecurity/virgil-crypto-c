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
from ._c_bridge import VscfHmac
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg import Alg
from .mac import Mac


class Hmac(Alg, Mac):
    """Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1)."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_hmac = VscfHmac()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_hmac.vscf_hmac_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_hmac.vscf_hmac_delete(self.ctx)

    def set_hash(self, hash):
        self._lib_vscf_hmac.vscf_hmac_use_hash(self.ctx, hash.c_impl)

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_hmac.vscf_hmac_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_hmac.vscf_hmac_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_hmac.vscf_hmac_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def digest_len(self):
        """Size of the digest (mac output) in bytes."""
        result = self._lib_vscf_hmac.vscf_hmac_digest_len(self.ctx)
        return result

    def mac(self, key, data):
        """Calculate MAC over given data."""
        d_key = Data(key)
        d_data = Data(data)
        mac = Buffer(self.digest_len())
        self._lib_vscf_hmac.vscf_hmac_mac(self.ctx, d_key.data, d_data.data, mac.c_buffer)
        return mac.get_bytes()

    def start(self, key):
        """Start a new MAC."""
        d_key = Data(key)
        self._lib_vscf_hmac.vscf_hmac_start(self.ctx, d_key.data)

    def update(self, data):
        """Add given data to the MAC."""
        d_data = Data(data)
        self._lib_vscf_hmac.vscf_hmac_update(self.ctx, d_data.data)

    def finish(self):
        """Accomplish MAC and return it's result (a message digest)."""
        mac = Buffer(self.digest_len())
        self._lib_vscf_hmac.vscf_hmac_finish(self.ctx, mac.c_buffer)
        return mac.get_bytes()

    def reset(self):
        """Prepare to authenticate a new message with the same key
        as the previous MAC operation."""
        self._lib_vscf_hmac.vscf_hmac_reset(self.ctx)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_hmac = VscfHmac()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_hmac = VscfHmac()
        inst.ctx = inst._lib_vscf_hmac.vscf_hmac_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_hmac.vscf_hmac_shallow_copy(value)
        self._c_impl = self._lib_vscf_hmac.vscf_hmac_impl(self.ctx)
