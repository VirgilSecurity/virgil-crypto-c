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
from ._c_bridge import VscfPem
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus


class Pem(object):
    """Simple PEM wrapper."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_pem = VscfPem()

    def wrapped_len(self, title, data_len):
        """Return length in bytes required to hold wrapped PEM format."""
        result = self._lib_vscf_pem.vscf_pem_wrapped_len(title, data_len)
        return result

    def wrap(self, title, data):
        """Takes binary data and wraps it to the simple PEM format - no
        additional information just header-base64-footer.
        Note, written buffer is NOT null-terminated."""
        d_data = Data(data)
        pem = Buffer(self.wrapped_len(title=title, data_len=len(data)))
        self._lib_vscf_pem.vscf_pem_wrap(title, d_data.data, pem.c_buffer)
        return pem.get_bytes()

    def unwrapped_len(self, pem_len):
        """Return length in bytes required to hold unwrapped binary."""
        result = self._lib_vscf_pem.vscf_pem_unwrapped_len(pem_len)
        return result

    def unwrap(self, pem):
        """Takes PEM data and extract binary data from it."""
        d_pem = Data(pem)
        data = Buffer(self.unwrapped_len(pem_len=len(pem)))
        status = self._lib_vscf_pem.vscf_pem_unwrap(d_pem.data, data.c_buffer)
        VscfStatus.handle_status(status)
        return data.get_bytes()

    def title(self, pem):
        """Returns PEM title if PEM data is valid, otherwise - empty data."""
        d_pem = Data(pem)
        result = self._lib_vscf_pem.vscf_pem_title(d_pem.data)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes
