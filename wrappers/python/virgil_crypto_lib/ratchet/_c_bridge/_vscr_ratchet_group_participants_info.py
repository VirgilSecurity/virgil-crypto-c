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


class vscr_ratchet_group_participants_info_t(Structure):
    pass


class VscrRatchetGroupParticipantsInfo(object):
    """Container for array of participants' info"""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.ratchet

    def vscr_ratchet_group_participants_info_new(self):
        vscr_ratchet_group_participants_info_new = self._lib.vscr_ratchet_group_participants_info_new
        vscr_ratchet_group_participants_info_new.argtypes = []
        vscr_ratchet_group_participants_info_new.restype = POINTER(vscr_ratchet_group_participants_info_t)
        return vscr_ratchet_group_participants_info_new()

    def vscr_ratchet_group_participants_info_delete(self, ctx):
        vscr_ratchet_group_participants_info_delete = self._lib.vscr_ratchet_group_participants_info_delete
        vscr_ratchet_group_participants_info_delete.argtypes = [POINTER(vscr_ratchet_group_participants_info_t)]
        vscr_ratchet_group_participants_info_delete.restype = None
        return vscr_ratchet_group_participants_info_delete(ctx)

    def vscr_ratchet_group_participants_info_new_size(self, size):
        """Creates new array for size elements"""
        vscr_ratchet_group_participants_info_new_size = self._lib.vscr_ratchet_group_participants_info_new_size
        vscr_ratchet_group_participants_info_new_size.argtypes = [c_uint]
        vscr_ratchet_group_participants_info_new_size.restype = POINTER(vscr_ratchet_group_participants_info_t)
        return vscr_ratchet_group_participants_info_new_size(size)

    def vscr_ratchet_group_participants_info_add_participant(self, ctx, id, pub_key):
        """Add participant info"""
        vscr_ratchet_group_participants_info_add_participant = self._lib.vscr_ratchet_group_participants_info_add_participant
        vscr_ratchet_group_participants_info_add_participant.argtypes = [POINTER(vscr_ratchet_group_participants_info_t), vsc_data_t, vsc_data_t]
        vscr_ratchet_group_participants_info_add_participant.restype = c_int
        return vscr_ratchet_group_participants_info_add_participant(ctx, id, pub_key)

    def vscr_ratchet_group_participants_info_shallow_copy(self, ctx):
        vscr_ratchet_group_participants_info_shallow_copy = self._lib.vscr_ratchet_group_participants_info_shallow_copy
        vscr_ratchet_group_participants_info_shallow_copy.argtypes = [POINTER(vscr_ratchet_group_participants_info_t)]
        vscr_ratchet_group_participants_info_shallow_copy.restype = POINTER(vscr_ratchet_group_participants_info_t)
        return vscr_ratchet_group_participants_info_shallow_copy(ctx)
