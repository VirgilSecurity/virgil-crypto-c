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
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_group_session_message import vscf_group_session_message_t


class vscf_group_session_ticket_t(Structure):
    pass


class VscfGroupSessionTicket(object):
    """Group ticket used to start group session, remove participants or proactive to rotate encryption key."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_group_session_ticket_new(self):
        vscf_group_session_ticket_new = self._lib.vscf_group_session_ticket_new
        vscf_group_session_ticket_new.argtypes = []
        vscf_group_session_ticket_new.restype = POINTER(vscf_group_session_ticket_t)
        return vscf_group_session_ticket_new()

    def vscf_group_session_ticket_delete(self, ctx):
        vscf_group_session_ticket_delete = self._lib.vscf_group_session_ticket_delete
        vscf_group_session_ticket_delete.argtypes = [POINTER(vscf_group_session_ticket_t)]
        vscf_group_session_ticket_delete.restype = None
        return vscf_group_session_ticket_delete(ctx)

    def vscf_group_session_ticket_use_rng(self, ctx, rng):
        """Random used to generate keys"""
        vscf_group_session_ticket_use_rng = self._lib.vscf_group_session_ticket_use_rng
        vscf_group_session_ticket_use_rng.argtypes = [POINTER(vscf_group_session_ticket_t), POINTER(vscf_impl_t)]
        vscf_group_session_ticket_use_rng.restype = None
        return vscf_group_session_ticket_use_rng(ctx, rng)

    def vscf_group_session_ticket_setup_defaults(self, ctx):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        vscf_group_session_ticket_setup_defaults = self._lib.vscf_group_session_ticket_setup_defaults
        vscf_group_session_ticket_setup_defaults.argtypes = [POINTER(vscf_group_session_ticket_t)]
        vscf_group_session_ticket_setup_defaults.restype = c_int
        return vscf_group_session_ticket_setup_defaults(ctx)

    def vscf_group_session_ticket_setup_ticket_as_new(self, ctx, session_id):
        """Set this ticket to start new group session."""
        vscf_group_session_ticket_setup_ticket_as_new = self._lib.vscf_group_session_ticket_setup_ticket_as_new
        vscf_group_session_ticket_setup_ticket_as_new.argtypes = [POINTER(vscf_group_session_ticket_t), vsc_data_t]
        vscf_group_session_ticket_setup_ticket_as_new.restype = c_int
        return vscf_group_session_ticket_setup_ticket_as_new(ctx, session_id)

    def vscf_group_session_ticket_get_ticket_message(self, ctx):
        """Returns message that should be sent to all participants using secure channel."""
        vscf_group_session_ticket_get_ticket_message = self._lib.vscf_group_session_ticket_get_ticket_message
        vscf_group_session_ticket_get_ticket_message.argtypes = [POINTER(vscf_group_session_ticket_t)]
        vscf_group_session_ticket_get_ticket_message.restype = POINTER(vscf_group_session_message_t)
        return vscf_group_session_ticket_get_ticket_message(ctx)

    def vscf_group_session_ticket_shallow_copy(self, ctx):
        vscf_group_session_ticket_shallow_copy = self._lib.vscf_group_session_ticket_shallow_copy
        vscf_group_session_ticket_shallow_copy.argtypes = [POINTER(vscf_group_session_ticket_t)]
        vscf_group_session_ticket_shallow_copy.restype = POINTER(vscf_group_session_ticket_t)
        return vscf_group_session_ticket_shallow_copy(ctx)
