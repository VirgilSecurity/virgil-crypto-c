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


class VscfPem(object):
    """Simple PEM wrapper."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_pem_wrapped_len(self, title, data_len):
        """Return length in bytes required to hold wrapped PEM format."""
        vscf_pem_wrapped_len = self._lib.vscf_pem_wrapped_len
        vscf_pem_wrapped_len.argtypes = [POINTER(c_char), c_size_t]
        vscf_pem_wrapped_len.restype = c_size_t
        return vscf_pem_wrapped_len(title, data_len)

    def vscf_pem_wrap(self, title, data, pem):
        """Takes binary data and wraps it to the simple PEM format - no
        additional information just header-base64-footer.
        Note, written buffer is NOT null-terminated."""
        vscf_pem_wrap = self._lib.vscf_pem_wrap
        vscf_pem_wrap.argtypes = [POINTER(c_char), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_pem_wrap.restype = None
        return vscf_pem_wrap(title, data, pem)

    def vscf_pem_unwrapped_len(self, pem_len):
        """Return length in bytes required to hold unwrapped binary."""
        vscf_pem_unwrapped_len = self._lib.vscf_pem_unwrapped_len
        vscf_pem_unwrapped_len.argtypes = [c_size_t]
        vscf_pem_unwrapped_len.restype = c_size_t
        return vscf_pem_unwrapped_len(pem_len)

    def vscf_pem_unwrap(self, pem, data):
        """Takes PEM data and extract binary data from it."""
        vscf_pem_unwrap = self._lib.vscf_pem_unwrap
        vscf_pem_unwrap.argtypes = [vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_pem_unwrap.restype = c_int
        return vscf_pem_unwrap(pem, data)

    def vscf_pem_title(self, pem):
        """Returns PEM title if PEM data is valid, otherwise - empty data."""
        vscf_pem_title = self._lib.vscf_pem_title
        vscf_pem_title.argtypes = [vsc_data_t]
        vscf_pem_title.restype = vsc_data_t
        return vscf_pem_title(pem)
