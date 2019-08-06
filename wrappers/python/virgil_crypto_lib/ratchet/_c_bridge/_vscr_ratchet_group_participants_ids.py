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
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vscr_ratchet_group_participants_ids_t(Structure):
    pass


class VscrRatchetGroupParticipantsIds(object):
    """Container for array of participants ids"""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.ratchet

    def vscr_ratchet_group_participants_ids_new(self):
        vscr_ratchet_group_participants_ids_new = self._lib.vscr_ratchet_group_participants_ids_new
        vscr_ratchet_group_participants_ids_new.argtypes = []
        vscr_ratchet_group_participants_ids_new.restype = POINTER(vscr_ratchet_group_participants_ids_t)
        return vscr_ratchet_group_participants_ids_new()

    def vscr_ratchet_group_participants_ids_delete(self, ctx):
        vscr_ratchet_group_participants_ids_delete = self._lib.vscr_ratchet_group_participants_ids_delete
        vscr_ratchet_group_participants_ids_delete.argtypes = [POINTER(vscr_ratchet_group_participants_ids_t)]
        vscr_ratchet_group_participants_ids_delete.restype = None
        return vscr_ratchet_group_participants_ids_delete(ctx)

    def vscr_ratchet_group_participants_ids_new_size(self, size):
        """Creates new array for size elements"""
        vscr_ratchet_group_participants_ids_new_size = self._lib.vscr_ratchet_group_participants_ids_new_size
        vscr_ratchet_group_participants_ids_new_size.argtypes = [c_uint]
        vscr_ratchet_group_participants_ids_new_size.restype = POINTER(vscr_ratchet_group_participants_ids_t)
        return vscr_ratchet_group_participants_ids_new_size(size)

    def vscr_ratchet_group_participants_ids_add_id(self, ctx, id):
        """Add participant id to array"""
        vscr_ratchet_group_participants_ids_add_id = self._lib.vscr_ratchet_group_participants_ids_add_id
        vscr_ratchet_group_participants_ids_add_id.argtypes = [POINTER(vscr_ratchet_group_participants_ids_t), vsc_data_t]
        vscr_ratchet_group_participants_ids_add_id.restype = None
        return vscr_ratchet_group_participants_ids_add_id(ctx, id)

    def vscr_ratchet_group_participants_ids_shallow_copy(self, ctx):
        vscr_ratchet_group_participants_ids_shallow_copy = self._lib.vscr_ratchet_group_participants_ids_shallow_copy
        vscr_ratchet_group_participants_ids_shallow_copy.argtypes = [POINTER(vscr_ratchet_group_participants_ids_t)]
        vscr_ratchet_group_participants_ids_shallow_copy.restype = POINTER(vscr_ratchet_group_participants_ids_t)
        return vscr_ratchet_group_participants_ids_shallow_copy(ctx)
