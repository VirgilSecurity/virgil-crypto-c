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
from ._vscf_error import vscf_error_t


class vscf_group_session_message_t(Structure):
    pass


class VscfGroupSessionMessage(object):
    """Class represents group session message"""

    # Max message len
    MAX_MESSAGE_LEN = 30188
    # Message version
    MESSAGE_VERSION = 1

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_group_session_message_new(self):
        vscf_group_session_message_new = self._lib.vscf_group_session_message_new
        vscf_group_session_message_new.argtypes = []
        vscf_group_session_message_new.restype = POINTER(vscf_group_session_message_t)
        return vscf_group_session_message_new()

    def vscf_group_session_message_delete(self, ctx):
        vscf_group_session_message_delete = self._lib.vscf_group_session_message_delete
        vscf_group_session_message_delete.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_delete.restype = None
        return vscf_group_session_message_delete(ctx)

    def vscf_group_session_message_get_type(self, ctx):
        """Returns message type."""
        vscf_group_session_message_get_type = self._lib.vscf_group_session_message_get_type
        vscf_group_session_message_get_type.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_get_type.restype = c_int
        return vscf_group_session_message_get_type(ctx)

    def vscf_group_session_message_get_session_id(self, ctx):
        """Returns session id.
        This method should be called only for group info type."""
        vscf_group_session_message_get_session_id = self._lib.vscf_group_session_message_get_session_id
        vscf_group_session_message_get_session_id.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_get_session_id.restype = vsc_data_t
        return vscf_group_session_message_get_session_id(ctx)

    def vscf_group_session_message_get_epoch(self, ctx):
        """Returns message epoch."""
        vscf_group_session_message_get_epoch = self._lib.vscf_group_session_message_get_epoch
        vscf_group_session_message_get_epoch.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_get_epoch.restype = c_uint
        return vscf_group_session_message_get_epoch(ctx)

    def vscf_group_session_message_serialize_len(self, ctx):
        """Buffer len to serialize this class."""
        vscf_group_session_message_serialize_len = self._lib.vscf_group_session_message_serialize_len
        vscf_group_session_message_serialize_len.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_serialize_len.restype = c_size_t
        return vscf_group_session_message_serialize_len(ctx)

    def vscf_group_session_message_serialize(self, ctx, output):
        """Serializes instance."""
        vscf_group_session_message_serialize = self._lib.vscf_group_session_message_serialize
        vscf_group_session_message_serialize.argtypes = [POINTER(vscf_group_session_message_t), POINTER(vsc_buffer_t)]
        vscf_group_session_message_serialize.restype = None
        return vscf_group_session_message_serialize(ctx, output)

    def vscf_group_session_message_deserialize(self, input, error):
        """Deserializes instance."""
        vscf_group_session_message_deserialize = self._lib.vscf_group_session_message_deserialize
        vscf_group_session_message_deserialize.argtypes = [vsc_data_t, POINTER(vscf_error_t)]
        vscf_group_session_message_deserialize.restype = POINTER(vscf_group_session_message_t)
        return vscf_group_session_message_deserialize(input, error)

    def vscf_group_session_message_shallow_copy(self, ctx):
        vscf_group_session_message_shallow_copy = self._lib.vscf_group_session_message_shallow_copy
        vscf_group_session_message_shallow_copy.argtypes = [POINTER(vscf_group_session_message_t)]
        vscf_group_session_message_shallow_copy.restype = POINTER(vscf_group_session_message_t)
        return vscf_group_session_message_shallow_copy(ctx)
