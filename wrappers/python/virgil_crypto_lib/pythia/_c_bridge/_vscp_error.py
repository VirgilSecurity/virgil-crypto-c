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


class vscp_error_t(Structure):
    _fields_ = [
        ("status", c_int)
    ]


class VscpError(object):
    """Error context.
    Can be used for sequential operations, i.e. parsers, to accumulate error.
    In this way operation is successful if all steps are successful, otherwise
    last occurred error code can be obtained."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.pythia

    def vscp_error_reset(self, ctx):
        """Reset context to the "no error" state."""
        vscp_error_reset = self._lib.vscp_error_reset
        vscp_error_reset.argtypes = [POINTER(vscp_error_t)]
        vscp_error_reset.restype = None
        return vscp_error_reset(ctx)

    def vscp_error_has_error(self, ctx):
        """Return true if status is not "success"."""
        vscp_error_has_error = self._lib.vscp_error_has_error
        vscp_error_has_error.argtypes = [POINTER(vscp_error_t)]
        vscp_error_has_error.restype = c_bool
        return vscp_error_has_error(ctx)

    def vscp_error_status(self, ctx):
        """Return error code."""
        vscp_error_status = self._lib.vscp_error_status
        vscp_error_status.argtypes = [POINTER(vscp_error_t)]
        vscp_error_status.restype = c_int
        return vscp_error_status(ctx)
