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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscr_error import vscr_error_t


class vscr_ratchet_group_message_t(Structure):
    pass


class VscrRatchetGroupMessage(object):
    """Class represents ratchet group message"""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.ratchet

    def vscr_ratchet_group_message_new(self):
        vscr_ratchet_group_message_new = self._lib.vscr_ratchet_group_message_new
        vscr_ratchet_group_message_new.argtypes = []
        vscr_ratchet_group_message_new.restype = POINTER(vscr_ratchet_group_message_t)
        return vscr_ratchet_group_message_new()

    def vscr_ratchet_group_message_delete(self, ctx):
        vscr_ratchet_group_message_delete = self._lib.vscr_ratchet_group_message_delete
        vscr_ratchet_group_message_delete.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_delete.restype = None
        return vscr_ratchet_group_message_delete(ctx)

    def vscr_ratchet_group_message_get_type(self, ctx):
        """Returns message type."""
        vscr_ratchet_group_message_get_type = self._lib.vscr_ratchet_group_message_get_type
        vscr_ratchet_group_message_get_type.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_get_type.restype = c_int
        return vscr_ratchet_group_message_get_type(ctx)

    def vscr_ratchet_group_message_get_session_id(self, ctx):
        """Returns session id.
        This method should be called only for group info type."""
        vscr_ratchet_group_message_get_session_id = self._lib.vscr_ratchet_group_message_get_session_id
        vscr_ratchet_group_message_get_session_id.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_get_session_id.restype = vsc_data_t
        return vscr_ratchet_group_message_get_session_id(ctx)

    def vscr_ratchet_group_message_get_sender_id(self, ctx):
        """Returns message sender id.
        This method should be called only for regular message type."""
        vscr_ratchet_group_message_get_sender_id = self._lib.vscr_ratchet_group_message_get_sender_id
        vscr_ratchet_group_message_get_sender_id.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_get_sender_id.restype = vsc_data_t
        return vscr_ratchet_group_message_get_sender_id(ctx)

    def vscr_ratchet_group_message_get_counter(self, ctx):
        """Returns message counter in current epoch."""
        vscr_ratchet_group_message_get_counter = self._lib.vscr_ratchet_group_message_get_counter
        vscr_ratchet_group_message_get_counter.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_get_counter.restype = c_uint
        return vscr_ratchet_group_message_get_counter(ctx)

    def vscr_ratchet_group_message_get_epoch(self, ctx):
        """Returns message epoch."""
        vscr_ratchet_group_message_get_epoch = self._lib.vscr_ratchet_group_message_get_epoch
        vscr_ratchet_group_message_get_epoch.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_get_epoch.restype = c_uint
        return vscr_ratchet_group_message_get_epoch(ctx)

    def vscr_ratchet_group_message_serialize_len(self, ctx):
        """Buffer len to serialize this class."""
        vscr_ratchet_group_message_serialize_len = self._lib.vscr_ratchet_group_message_serialize_len
        vscr_ratchet_group_message_serialize_len.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_serialize_len.restype = c_size_t
        return vscr_ratchet_group_message_serialize_len(ctx)

    def vscr_ratchet_group_message_serialize(self, ctx, output):
        """Serializes instance."""
        vscr_ratchet_group_message_serialize = self._lib.vscr_ratchet_group_message_serialize
        vscr_ratchet_group_message_serialize.argtypes = [POINTER(vscr_ratchet_group_message_t), POINTER(vsc_buffer_t)]
        vscr_ratchet_group_message_serialize.restype = None
        return vscr_ratchet_group_message_serialize(ctx, output)

    def vscr_ratchet_group_message_deserialize(self, input, error):
        """Deserializes instance."""
        vscr_ratchet_group_message_deserialize = self._lib.vscr_ratchet_group_message_deserialize
        vscr_ratchet_group_message_deserialize.argtypes = [vsc_data_t, POINTER(vscr_error_t)]
        vscr_ratchet_group_message_deserialize.restype = POINTER(vscr_ratchet_group_message_t)
        return vscr_ratchet_group_message_deserialize(input, error)

    def vscr_ratchet_group_message_shallow_copy(self, ctx):
        vscr_ratchet_group_message_shallow_copy = self._lib.vscr_ratchet_group_message_shallow_copy
        vscr_ratchet_group_message_shallow_copy.argtypes = [POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_message_shallow_copy.restype = POINTER(vscr_ratchet_group_message_t)
        return vscr_ratchet_group_message_shallow_copy(ctx)
