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
from ._c_bridge import VscfGroupSessionMessage
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfStatus


class GroupSessionMessage(object):
    """Class represents group session message"""

    # Max message len
    MAX_MESSAGE_LEN = 30188
    # Message version
    MESSAGE_VERSION = 1

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_group_session_message = VscfGroupSessionMessage()
        self.ctx = self._lib_vscf_group_session_message.vscf_group_session_message_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_group_session_message.vscf_group_session_message_delete(self.ctx)

    def get_type(self):
        """Returns message type."""
        result = self._lib_vscf_group_session_message.vscf_group_session_message_get_type(self.ctx)
        return result

    def get_session_id(self):
        """Returns session id.
        This method should be called only for group info type."""
        result = self._lib_vscf_group_session_message.vscf_group_session_message_get_session_id(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def get_epoch(self):
        """Returns message epoch."""
        result = self._lib_vscf_group_session_message.vscf_group_session_message_get_epoch(self.ctx)
        return result

    def serialize_len(self):
        """Buffer len to serialize this class."""
        result = self._lib_vscf_group_session_message.vscf_group_session_message_serialize_len(self.ctx)
        return result

    def serialize(self):
        """Serializes instance."""
        output = Buffer(self.serialize_len())
        self._lib_vscf_group_session_message.vscf_group_session_message_serialize(self.ctx, output.c_buffer)
        return output.get_bytes()

    def deserialize(self, input):
        """Deserializes instance."""
        d_input = Data(input)
        error = vscf_error_t()
        result = self._lib_vscf_group_session_message.vscf_group_session_message_deserialize(d_input.data, error)
        VscfStatus.handle_status(error.status)
        instance = GroupSessionMessage.take_c_ctx(result)
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_group_session_message = VscfGroupSessionMessage()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_group_session_message = VscfGroupSessionMessage()
        inst.ctx = inst._lib_vscf_group_session_message.vscf_group_session_message_shallow_copy(c_ctx)
        return inst
