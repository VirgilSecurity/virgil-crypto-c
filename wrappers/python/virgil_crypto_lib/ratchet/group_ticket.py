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
from ._c_bridge import VscrRatchetGroupTicket
from ._c_bridge import VscrStatus
from virgil_crypto_lib.common._c_bridge import Data
from .group_message import GroupMessage


class GroupTicket(object):
    """Group ticket used to start group session or change participants."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_group_ticket = VscrRatchetGroupTicket()
        self.ctx = self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_delete(self.ctx)

    def set_rng(self, rng):
        """Random used to generate keys"""
        self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_use_rng(self.ctx, rng.c_impl)

    def setup_defaults(self):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        status = self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_setup_defaults(self.ctx)
        VscrStatus.handle_status(status)

    def setup_ticket_as_new(self, session_id):
        """Set this ticket to start new group session."""
        d_session_id = Data(session_id)
        status = self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_setup_ticket_as_new(self.ctx, d_session_id.data)
        VscrStatus.handle_status(status)

    def get_ticket_message(self):
        """Returns message that should be sent to all participants using secure channel."""
        result = self._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_get_ticket_message(self.ctx)
        instance = GroupMessage.use_c_ctx(result)
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_ticket = VscrRatchetGroupTicket()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_ticket = VscrRatchetGroupTicket()
        inst.ctx = inst._lib_vscr_ratchet_group_ticket.vscr_ratchet_group_ticket_shallow_copy(c_ctx)
        return inst
