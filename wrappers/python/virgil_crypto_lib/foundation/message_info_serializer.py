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
from abc import *


class MessageInfoSerializer(object):
    """Provide interface for "message info" class serialization."""
    __metaclass__ = ABCMeta

    PREFIX_LEN = 0

    @abstractmethod
    def serialized_len(self, message_info):
        """Return buffer size enough to hold serialized message info."""
        raise NotImplementedError()

    @abstractmethod
    def serialize(self, message_info):
        """Serialize class "message info"."""
        raise NotImplementedError()

    @abstractmethod
    def read_prefix(self, data):
        """Read message info prefix from the given data, and if it is valid,
        return a length of bytes of the whole message info.

        Zero returned if length can not be determined from the given data,
        and this means that there is no message info at the data beginning."""
        raise NotImplementedError()

    @abstractmethod
    def deserialize(self, data):
        """Deserialize class "message info"."""
        raise NotImplementedError()
