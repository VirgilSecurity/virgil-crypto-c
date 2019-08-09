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
from ._c_bridge import VscfRecipientCipher
from virgil_crypto_lib.common._c_bridge import Data
from .message_info_custom_params import MessageInfoCustomParams
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Buffer


class RecipientCipher(object):
    """This class provides hybrid encryption algorithm that combines symmetric
    cipher for data encryption and asymmetric cipher and password based
    cipher for symmetric key encryption."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_recipient_cipher = VscfRecipientCipher()
        self.ctx = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_use_random(self.ctx, random.c_impl)

    def set_encryption_cipher(self, encryption_cipher):
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_use_encryption_cipher(self.ctx, encryption_cipher.c_impl)

    def add_key_recipient(self, recipient_id, public_key):
        """Add recipient defined with id and public key."""
        d_recipient_id = Data(recipient_id)
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_add_key_recipient(self.ctx, d_recipient_id.data, public_key.c_impl)

    def clear_recipients(self):
        """Remove all recipients."""
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_clear_recipients(self.ctx)

    def custom_params(self):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_custom_params(self.ctx)
        instance = MessageInfoCustomParams.use_c_ctx(result)
        return instance

    def message_info_len(self):
        """Return buffer length required to hold message info returned by the
        "start encryption" method.
        Precondition: all recipients and custom parameters should be set."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_message_info_len(self.ctx)
        return result

    def start_encryption(self):
        """Start encryption process."""
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_encryption(self.ctx)
        VscfStatus.handle_status(status)

    def pack_message_info(self):
        """Return serialized message info to the buffer.

        Precondition: this method can be called after "start encryption".
        Precondition: this method can be called before "finish encryption".

        Note, store message info to use it for decryption process,
        or place it at the encrypted data beginning (embedding).

        Return message info - recipients public information,
        algorithm information, etc."""
        message_info = Buffer(self.message_info_len())
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_pack_message_info(self.ctx, message_info.c_buffer)
        return message_info.get_bytes()

    def encryption_out_len(self, data_len):
        """Return buffer length required to hold output of the method
        "process encryption" and method "finish" during encryption."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_encryption_out_len(self.ctx, data_len)
        return result

    def process_encryption(self, data):
        """Process encryption of a new portion of data."""
        d_data = Data(data)
        out = Buffer(self.encryption_out_len(data_len=len(data)))
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_process_encryption(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def finish_encryption(self):
        """Accomplish encryption."""
        out = Buffer(self.encryption_out_len(data_len=0))
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_finish_encryption(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def start_decryption_with_key(self, recipient_id, private_key, message_info):
        """Initiate decryption process with a recipient private key.
        Message info can be empty if it was embedded to encrypted data."""
        d_recipient_id = Data(recipient_id)
        d_message_info = Data(message_info)
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_decryption_with_key(self.ctx, d_recipient_id.data, private_key.c_impl, d_message_info.data)
        VscfStatus.handle_status(status)

    def decryption_out_len(self, data_len):
        """Return buffer length required to hold output of the method
        "process decryption" and method "finish" during decryption."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_decryption_out_len(self.ctx, data_len)
        return result

    def process_decryption(self, data):
        """Process with a new portion of data.
        Return error if data can not be encrypted or decrypted."""
        d_data = Data(data)
        out = Buffer(self.decryption_out_len(data_len=len(data)))
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_process_decryption(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def finish_decryption(self):
        """Accomplish decryption."""
        out = Buffer(self.decryption_out_len(data_len=0))
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_finish_decryption(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_recipient_cipher = VscfRecipientCipher()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_recipient_cipher = VscfRecipientCipher()
        inst.ctx = inst._lib_vscf_recipient_cipher.vscf_recipient_cipher_shallow_copy(c_ctx)
        return inst
