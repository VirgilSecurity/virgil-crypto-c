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


from ctypes import *
from ._c_bridge import VscStrMutable
from virgil_crypto_lib.common._c_bridge import Data


class StrMutable(object):
    """Light version of the class "str buffer".

    Note, this class always handles a null-terminated string.
    Note, this class might be used to store copied strings within objects.
    Note, this class' ownership can not be retained.
    Note, this class can not be used as part of any public interface."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsc_str_mutable = VscStrMutable()

    def is_valid(self):
        """Returns true if underlying string is defined."""
        result = self._lib_vsc_str_mutable.vsc_str_mutable_is_valid(self.ctx)
        return result

    def as_str(self):
        """Returns immutable str."""
        result = self._lib_vsc_str_mutable.vsc_str_mutable_as_str(self.ctx)
        return result

    def as_data(self):
        """Returns immutable str as bytes."""
        result = self._lib_vsc_str_mutable.vsc_str_mutable_as_data(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def init(self, self):
        """Init underlying structure."""
        self._lib_vsc_str_mutable.vsc_str_mutable_init(self.ctx)

    def release(self, self):
        """Deallocate underlying string."""
        self._lib_vsc_str_mutable.vsc_str_mutable_release(self.ctx)
