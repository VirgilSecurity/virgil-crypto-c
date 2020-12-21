# Copyright (C) 2015-2020 Virgil Security, Inc.
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
from ._vsc_str import vsc_str_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vsc_str_mutable_t(Structure):
    _fields_ = [
        ("chars", char),
        ("len", size)
    ]


class VscStrMutable(object):
    """Light version of the class "str buffer".

    Note, this class always handles a null-terminated string.
    Note, this class might be used to store copied strings within objects.
    Note, this class' ownership can not be retained.
    Note, this class can not be used as part of any public interface."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.common

    def vsc_str_mutable_is_valid(self, ctx):
        """Returns true if underlying string is defined."""
        vsc_str_mutable_is_valid = self._lib.vsc_str_mutable_is_valid
        vsc_str_mutable_is_valid.argtypes = [POINTER(vsc_str_mutable_t)]
        vsc_str_mutable_is_valid.restype = c_bool
        return vsc_str_mutable_is_valid(ctx)

    def vsc_str_mutable_as_str(self, ctx):
        """Returns immutable str."""
        vsc_str_mutable_as_str = self._lib.vsc_str_mutable_as_str
        vsc_str_mutable_as_str.argtypes = [POINTER(vsc_str_mutable_t)]
        vsc_str_mutable_as_str.restype = vsc_str_t
        return vsc_str_mutable_as_str(ctx)

    def vsc_str_mutable_as_data(self, ctx):
        """Returns immutable str as bytes."""
        vsc_str_mutable_as_data = self._lib.vsc_str_mutable_as_data
        vsc_str_mutable_as_data.argtypes = [POINTER(vsc_str_mutable_t)]
        vsc_str_mutable_as_data.restype = vsc_data_t
        return vsc_str_mutable_as_data(ctx)

    def vsc_str_mutable_init(self, self):
        """Init underlying structure."""
        vsc_str_mutable_init = self._lib.vsc_str_mutable_init
        vsc_str_mutable_init.argtypes = [POINTER(vsc_str_mutable_t)]
        vsc_str_mutable_init.restype = None
        return vsc_str_mutable_init(self)

    def vsc_str_mutable_release(self, self):
        """Deallocate underlying string."""
        vsc_str_mutable_release = self._lib.vsc_str_mutable_release
        vsc_str_mutable_release.argtypes = [POINTER(vsc_str_mutable_t)]
        vsc_str_mutable_release.restype = None
        return vsc_str_mutable_release(self)
