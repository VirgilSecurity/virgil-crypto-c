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
from ._c_bridge import VscfBase64
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus


class Base64(object):
    """Implementation of the Base64 algorithm RFC 1421 and RFC 2045."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_base64 = VscfBase64()

    def encoded_len(self, data_len):
        """Calculate length in bytes required to hold an encoded base64 string."""
        result = self._lib_vscf_base64.vscf_base64_encoded_len(data_len)
        return result

    def encode(self, data):
        """Encode given data to the base64 format.
        Note, written buffer is NOT null-terminated."""
        d_data = Data(data)
        str = Buffer(self.encoded_len(data_len=len(data)))
        self._lib_vscf_base64.vscf_base64_encode(d_data.data, str.c_buffer)
        return str.get_bytes()

    def decoded_len(self, str_len):
        """Calculate length in bytes required to hold a decoded base64 string."""
        result = self._lib_vscf_base64.vscf_base64_decoded_len(str_len)
        return result

    def decode(self, str):
        """Decode given data from the base64 format."""
        d_str = Data(str)
        data = Buffer(self.decoded_len(str_len=len(str)))
        status = self._lib_vscf_base64.vscf_base64_decode(d_str.data, data.c_buffer)
        VscfStatus.handle_status(status)
        return data.get_bytes()
