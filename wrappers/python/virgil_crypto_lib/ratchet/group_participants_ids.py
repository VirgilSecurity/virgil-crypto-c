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
from ._c_bridge import VscrRatchetGroupParticipantsIds
from virgil_crypto_lib.common._c_bridge import Data


class GroupParticipantsIds(object):
    """Container for array of participants ids"""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_group_participants_ids = VscrRatchetGroupParticipantsIds()
        self.ctx = self._lib_vscr_ratchet_group_participants_ids.vscr_ratchet_group_participants_ids_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_group_participants_ids.vscr_ratchet_group_participants_ids_delete(self.ctx)

    @classmethod
    def size(cls, size):
        """Creates new array for size elements"""
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_ids = VscrRatchetGroupParticipantsIds()
        inst.ctx = inst._lib_vscr_ratchet_group_participants_ids.vscr_ratchet_group_participants_ids_new_size(size)
        return inst

    def add_id(self, id):
        """Add participant id to array"""
        d_id = Data(id)
        self._lib_vscr_ratchet_group_participants_ids.vscr_ratchet_group_participants_ids_add_id(self.ctx, d_id.data)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_ids = VscrRatchetGroupParticipantsIds()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_participants_ids = VscrRatchetGroupParticipantsIds()
        inst.ctx = inst._lib_vscr_ratchet_group_participants_ids.vscr_ratchet_group_participants_ids_shallow_copy(c_ctx)
        return inst
