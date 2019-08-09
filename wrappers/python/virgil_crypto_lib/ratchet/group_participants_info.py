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
from ._c_bridge import VscrRatchetGroupParticipantsInfo
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge import VscrStatus


class GroupParticipantsInfo(object):
    """Container for array of participants' info"""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_group_participants_info = VscrRatchetGroupParticipantsInfo()
        self.ctx = self._lib_vscr_ratchet_group_participants_info.vscr_ratchet_group_participants_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_group_participants_info.vscr_ratchet_group_participants_info_delete(self.ctx)

    @classmethod
    def size(cls, size):
        """Creates new array for size elements"""
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_info = VscrRatchetGroupParticipantsInfo()
        inst.ctx = inst._lib_vscr_ratchet_group_participants_info.vscr_ratchet_group_participants_info_new_size(size)
        return inst

    def add_participant(self, id, pub_key):
        """Add participant info"""
        d_id = Data(id)
        d_pub_key = Data(pub_key)
        status = self._lib_vscr_ratchet_group_participants_info.vscr_ratchet_group_participants_info_add_participant(self.ctx, d_id.data, d_pub_key.data)
        VscrStatus.handle_status(status)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_info = VscrRatchetGroupParticipantsInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_info = VscrRatchetGroupParticipantsInfo()
        inst.ctx = inst._lib_vscr_ratchet_group_participants_info.vscr_ratchet_group_participants_info_shallow_copy(c_ctx)
        return inst
