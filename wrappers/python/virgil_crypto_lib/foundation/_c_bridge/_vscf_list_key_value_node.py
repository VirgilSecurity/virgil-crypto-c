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


class vscf_list_key_value_node_t(Structure):
    pass


class VscfListKeyValueNode(object):
    """Double linked list node with key and value."""

    def vscf_list_key_value_node_new(self):
        vscf_list_key_value_node_new = self._lib.vscf_list_key_value_node_new
        vscf_list_key_value_node_new.argtypes = []
        vscf_list_key_value_node_new.restype = POINTER(vscf_list_key_value_node_t)
        return vscf_list_key_value_node_new()

    def vscf_list_key_value_node_delete(self, ctx):
        vscf_list_key_value_node_delete = self._lib.vscf_list_key_value_node_delete
        vscf_list_key_value_node_delete.argtypes = [POINTER(vscf_list_key_value_node_t)]
        vscf_list_key_value_node_delete.restype = None
        return vscf_list_key_value_node_delete(ctx)

    def vscf_list_key_value_node_shallow_copy(self, ctx):
        vscf_list_key_value_node_shallow_copy = self._lib.vscf_list_key_value_node_shallow_copy
        vscf_list_key_value_node_shallow_copy.argtypes = [POINTER(vscf_list_key_value_node_t)]
        vscf_list_key_value_node_shallow_copy.restype = POINTER(vscf_list_key_value_node_t)
        return vscf_list_key_value_node_shallow_copy(ctx)
