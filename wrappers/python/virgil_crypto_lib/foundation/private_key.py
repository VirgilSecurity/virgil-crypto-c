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


class PrivateKey(object):
    """Contains private part of the key."""
    __metaclass__ = ABCMeta

    # Define whether a private key can be exported or not.
    CAN_EXPORT_PRIVATE_KEY = 0
    # Define whether a private key can be imported or not.
    CAN_IMPORT_PRIVATE_KEY = 1

    @abstractmethod
    def extract_public_key(self):
        """Extract public part of the key."""
        raise NotImplementedError()

    @abstractmethod
    def export_private_key(self):
        """Export private key in the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be exported in format defined in
        RFC 3447 Appendix A.1.2."""
        raise NotImplementedError()

    @abstractmethod
    def exported_private_key_len(self):
        """Return length in bytes required to hold exported private key."""
        raise NotImplementedError()

    @abstractmethod
    def import_private_key(self, data):
        """Import private key from the binary format.

        Binary format must be defined in the key specification.
        For instance, RSA private key must be imported from the format defined in
        RFC 3447 Appendix A.1.2."""
        raise NotImplementedError()