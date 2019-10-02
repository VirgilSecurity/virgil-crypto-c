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


class VirgilCryptoPythiaError(Exception):
    pass


class VscpStatus(object):
    """Defines the library status codes."""

    # No errors was occurred.
    SUCCESS = 0
    # This error should not be returned if assertions is enabled.
    ERROR_BAD_ARGUMENTS = -1
    # Underlying pythia library returns -1.
    ERROR_PYTHIA_INNER_FAIL = -200
    # Underlying random number generator failed.
    ERROR_RNG_FAILED = -202

    STATUS_DICT = {
        0: "No errors was occurred.",
        -1: "This error should not be returned if assertions is enabled.",
        -200: "Underlying pythia library returns -1.",
        -202: "Underlying random number generator failed."
    }

    @classmethod
    def handle_status(cls, status):
        """Handle low level lib status"""
        if status != 0:
            try:
                raise VirgilCryptoPythiaError(cls.STATUS_DICT[status])
            except KeyError:
                raise VirgilCryptoPythiaError("Unknown error")
