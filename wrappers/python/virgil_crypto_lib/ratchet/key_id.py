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
from ._c_bridge import VscrRatchetKeyId
from .common import Common
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscrStatus


class KeyId(object):
    """Utils class for working with keys formats."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_key_id = VscrRatchetKeyId()
        self.ctx = self._lib_vscr_ratchet_key_id.vscr_ratchet_key_id_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_key_id.vscr_ratchet_key_id_delete(self.ctx)

    def compute_public_key_id(self, public_key):
        """Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key"""
        d_public_key = Data(public_key)
        key_id = Buffer(Common.KEY_ID_LEN)
        status = self._lib_vscr_ratchet_key_id.vscr_ratchet_key_id_compute_public_key_id(self.ctx, d_public_key.data, key_id.c_buffer)
        VscrStatus.handle_status(status)
        return key_id.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_key_id = VscrRatchetKeyId()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_key_id = VscrRatchetKeyId()
        inst.ctx = inst._lib_vscr_ratchet_key_id.vscr_ratchet_key_id_shallow_copy(c_ctx)
        return inst
