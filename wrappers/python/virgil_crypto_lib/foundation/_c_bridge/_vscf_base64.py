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


class VscfBase64(object):
    """Implementation of the Base64 algorithm RFC 1421 and RFC 2045."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_base64_encoded_len(self, data_len):
        """Calculate length in bytes required to hold an encoded base64 string."""
        vscf_base64_encoded_len = self._lib.vscf_base64_encoded_len
        vscf_base64_encoded_len.argtypes = [c_size_t]
        vscf_base64_encoded_len.restype = c_size_t
        return vscf_base64_encoded_len(data_len)

    def vscf_base64_encode(self, data, str):
        """Encode given data to the base64 format.
        Note, written buffer is NOT null-terminated."""
        vscf_base64_encode = self._lib.vscf_base64_encode
        vscf_base64_encode.argtypes = [vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_base64_encode.restype = None
        return vscf_base64_encode(data, str)

    def vscf_base64_decoded_len(self, str_len):
        """Calculate length in bytes required to hold a decoded base64 string."""
        vscf_base64_decoded_len = self._lib.vscf_base64_decoded_len
        vscf_base64_decoded_len.argtypes = [c_size_t]
        vscf_base64_decoded_len.restype = c_size_t
        return vscf_base64_decoded_len(str_len)

    def vscf_base64_decode(self, str, data):
        """Decode given data from the base64 format."""
        vscf_base64_decode = self._lib.vscf_base64_decode
        vscf_base64_decode.argtypes = [vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_base64_decode.restype = c_int
        return vscf_base64_decode(str, data)
