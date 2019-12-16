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
from ._c_bridge import VscfStatus
from .message_info_custom_params import MessageInfoCustomParams
from virgil_crypto_lib.common._c_bridge import Buffer
from .signer_info_list import SignerInfoList


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

    def set_encryption_padding(self, encryption_padding):
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_use_encryption_padding(self.ctx, encryption_padding.c_impl)

    def set_padding_params(self, padding_params):
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_use_padding_params(self.ctx, padding_params.ctx)

    def set_signer_hash(self, signer_hash):
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_use_signer_hash(self.ctx, signer_hash.c_impl)

    def has_key_recipient(self, recipient_id):
        """Return true if a key recipient with a given id has been added.
        Note, operation has O(N) time complexity."""
        d_recipient_id = Data(recipient_id)
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_has_key_recipient(self.ctx, d_recipient_id.data)
        return result

    def add_key_recipient(self, recipient_id, public_key):
        """Add recipient defined with id and public key."""
        d_recipient_id = Data(recipient_id)
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_add_key_recipient(self.ctx, d_recipient_id.data, public_key.c_impl)

    def clear_recipients(self):
        """Remove all recipients."""
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_clear_recipients(self.ctx)

    def add_signer(self, signer_id, private_key):
        """Add identifier and private key to sign initial plain text.
        Return error if the private key can not sign."""
        d_signer_id = Data(signer_id)
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_add_signer(self.ctx, d_signer_id.data, private_key.c_impl)
        VscfStatus.handle_status(status)

    def clear_signers(self):
        """Remove all signers."""
        self._lib_vscf_recipient_cipher.vscf_recipient_cipher_clear_signers(self.ctx)

    def custom_params(self):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_custom_params(self.ctx)
        instance = MessageInfoCustomParams.use_c_ctx(result)
        return instance

    def start_encryption(self):
        """Start encryption process."""
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_encryption(self.ctx)
        VscfStatus.handle_status(status)

    def start_signed_encryption(self, data_size):
        """Start encryption process with known plain text size.

        Precondition: At least one signer should be added.
        Note, store message info footer as well."""
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_signed_encryption(self.ctx, data_size)
        VscfStatus.handle_status(status)

    def message_info_len(self):
        """Return buffer length required to hold message info returned by the
        "pack message info" method.
        Precondition: all recipients and custom parameters should be set."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_message_info_len(self.ctx)
        return result

    def pack_message_info(self):
        """Return serialized message info to the buffer.

        Precondition: this method should be called after "start encryption".
        Precondition: this method should be called before "finish encryption".

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
        Message Info can be empty if it was embedded to encrypted data."""
        d_recipient_id = Data(recipient_id)
        d_message_info = Data(message_info)
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_decryption_with_key(self.ctx, d_recipient_id.data, private_key.c_impl, d_message_info.data)
        VscfStatus.handle_status(status)

    def start_verified_decryption_with_key(self, recipient_id, private_key, message_info, message_info_footer):
        """Initiate decryption process with a recipient private key.
        Message Info can be empty if it was embedded to encrypted data.
        Message Info footer can be empty if it was embedded to encrypted data.
        If footer was embedded, method "start decryption with key" can be used."""
        d_recipient_id = Data(recipient_id)
        d_message_info = Data(message_info)
        d_message_info_footer = Data(message_info_footer)
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_start_verified_decryption_with_key(self.ctx, d_recipient_id.data, private_key.c_impl, d_message_info.data, d_message_info_footer.data)
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

    def is_data_signed(self):
        """Return true if data was signed by a sender.

        Precondition: this method should be called after "finish decryption"."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_is_data_signed(self.ctx)
        return result

    def signer_infos(self):
        """Return information about signers that sign data.

        Precondition: this method should be called after "finish decryption".
        Precondition: method "is data signed" returns true."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_signer_infos(self.ctx)
        instance = SignerInfoList.use_c_ctx(result)
        return instance

    def verify_signer_info(self, signer_info, public_key):
        """Verify given cipher info."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_verify_signer_info(self.ctx, signer_info.ctx, public_key.c_impl)
        return result

    def message_info_footer_len(self):
        """Return buffer length required to hold message footer returned by the
        "pack message footer" method.

        Precondition: this method should be called after "finish encryption"."""
        result = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_message_info_footer_len(self.ctx)
        return result

    def pack_message_info_footer(self):
        """Return serialized message info footer to the buffer.

        Precondition: this method should be called after "finish encryption".

        Note, store message info to use it for verified decryption process,
        or place it at the encrypted data ending (embedding).

        Return message info footer - signers public information, etc."""
        out = Buffer(self.message_info_footer_len())
        status = self._lib_vscf_recipient_cipher.vscf_recipient_cipher_pack_message_info_footer(self.ctx, out.c_buffer)
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
