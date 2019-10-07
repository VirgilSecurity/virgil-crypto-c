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


class Cipher(object):
    """Provide interface for symmetric ciphers."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def set_nonce(self, nonce):
        """Setup IV or nonce."""
        raise NotImplementedError()

    @abstractmethod
    def set_key(self, key):
        """Set cipher encryption / decryption key."""
        raise NotImplementedError()

    @abstractmethod
    def start_encryption(self):
        """Start sequential encryption."""
        raise NotImplementedError()

    @abstractmethod
    def start_decryption(self):
        """Start sequential decryption."""
        raise NotImplementedError()

    @abstractmethod
    def update(self, data):
        """Process encryption or decryption of the given data chunk."""
        raise NotImplementedError()

    @abstractmethod
    def out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an current mode.
        Pass zero length to define buffer length of the method "finish"."""
        raise NotImplementedError()

    @abstractmethod
    def encrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an encryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        raise NotImplementedError()

    @abstractmethod
    def decrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an decryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        raise NotImplementedError()

    @abstractmethod
    def finish(self):
        """Accomplish encryption or decryption process."""
        raise NotImplementedError()
