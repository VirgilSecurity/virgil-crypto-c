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
from ._vscf_password_recipient_info import vscf_password_recipient_info_t


class vscf_password_recipient_info_list_t(Structure):
    pass


class VscfPasswordRecipientInfoList(object):
    """Handles a list of "password recipient info" class objects."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_password_recipient_info_list_new(self):
        vscf_password_recipient_info_list_new = self._lib.vscf_password_recipient_info_list_new
        vscf_password_recipient_info_list_new.argtypes = []
        vscf_password_recipient_info_list_new.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_password_recipient_info_list_new()

    def vscf_password_recipient_info_list_delete(self, ctx):
        vscf_password_recipient_info_list_delete = self._lib.vscf_password_recipient_info_list_delete
        vscf_password_recipient_info_list_delete.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_delete.restype = None
        return vscf_password_recipient_info_list_delete(ctx)

    def vscf_password_recipient_info_list_add(self, ctx, password_recipient_info):
        """Add new item to the list.
        Note, ownership is transfered."""
        vscf_password_recipient_info_list_add = self._lib.vscf_password_recipient_info_list_add
        vscf_password_recipient_info_list_add.argtypes = [POINTER(vscf_password_recipient_info_list_t), POINTER(vscf_password_recipient_info_t)]
        vscf_password_recipient_info_list_add.restype = None
        return vscf_password_recipient_info_list_add(ctx, password_recipient_info)

    def vscf_password_recipient_info_list_has_item(self, ctx):
        """Return true if given list has item."""
        vscf_password_recipient_info_list_has_item = self._lib.vscf_password_recipient_info_list_has_item
        vscf_password_recipient_info_list_has_item.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_has_item.restype = c_bool
        return vscf_password_recipient_info_list_has_item(ctx)

    def vscf_password_recipient_info_list_item(self, ctx):
        """Return list item."""
        vscf_password_recipient_info_list_item = self._lib.vscf_password_recipient_info_list_item
        vscf_password_recipient_info_list_item.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_item.restype = POINTER(vscf_password_recipient_info_t)
        return vscf_password_recipient_info_list_item(ctx)

    def vscf_password_recipient_info_list_has_next(self, ctx):
        """Return true if list has next item."""
        vscf_password_recipient_info_list_has_next = self._lib.vscf_password_recipient_info_list_has_next
        vscf_password_recipient_info_list_has_next.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_has_next.restype = c_bool
        return vscf_password_recipient_info_list_has_next(ctx)

    def vscf_password_recipient_info_list_next(self, ctx):
        """Return next list node if exists, or NULL otherwise."""
        vscf_password_recipient_info_list_next = self._lib.vscf_password_recipient_info_list_next
        vscf_password_recipient_info_list_next.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_next.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_password_recipient_info_list_next(ctx)

    def vscf_password_recipient_info_list_has_prev(self, ctx):
        """Return true if list has previous item."""
        vscf_password_recipient_info_list_has_prev = self._lib.vscf_password_recipient_info_list_has_prev
        vscf_password_recipient_info_list_has_prev.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_has_prev.restype = c_bool
        return vscf_password_recipient_info_list_has_prev(ctx)

    def vscf_password_recipient_info_list_prev(self, ctx):
        """Return previous list node if exists, or NULL otherwise."""
        vscf_password_recipient_info_list_prev = self._lib.vscf_password_recipient_info_list_prev
        vscf_password_recipient_info_list_prev.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_prev.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_password_recipient_info_list_prev(ctx)

    def vscf_password_recipient_info_list_clear(self, ctx):
        """Remove all items."""
        vscf_password_recipient_info_list_clear = self._lib.vscf_password_recipient_info_list_clear
        vscf_password_recipient_info_list_clear.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_clear.restype = None
        return vscf_password_recipient_info_list_clear(ctx)

    def vscf_password_recipient_info_list_shallow_copy(self, ctx):
        vscf_password_recipient_info_list_shallow_copy = self._lib.vscf_password_recipient_info_list_shallow_copy
        vscf_password_recipient_info_list_shallow_copy.argtypes = [POINTER(vscf_password_recipient_info_list_t)]
        vscf_password_recipient_info_list_shallow_copy.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_password_recipient_info_list_shallow_copy(ctx)
