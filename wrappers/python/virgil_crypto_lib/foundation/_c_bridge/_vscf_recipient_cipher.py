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
from ._vscf_padding_params import vscf_padding_params_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_message_info_custom_params import vscf_message_info_custom_params_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_signer_info_list import vscf_signer_info_list_t
from ._vscf_signer_info import vscf_signer_info_t


class vscf_recipient_cipher_t(Structure):
    pass


class VscfRecipientCipher(object):
    """This class provides hybrid encryption algorithm that combines symmetric
    cipher for data encryption and asymmetric cipher and password based
    cipher for symmetric key encryption."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_recipient_cipher_new(self):
        vscf_recipient_cipher_new = self._lib.vscf_recipient_cipher_new
        vscf_recipient_cipher_new.argtypes = []
        vscf_recipient_cipher_new.restype = POINTER(vscf_recipient_cipher_t)
        return vscf_recipient_cipher_new()

    def vscf_recipient_cipher_delete(self, ctx):
        vscf_recipient_cipher_delete = self._lib.vscf_recipient_cipher_delete
        vscf_recipient_cipher_delete.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_delete.restype = None
        return vscf_recipient_cipher_delete(ctx)

    def vscf_recipient_cipher_use_random(self, ctx, random):
        vscf_recipient_cipher_use_random = self._lib.vscf_recipient_cipher_use_random
        vscf_recipient_cipher_use_random.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_impl_t)]
        vscf_recipient_cipher_use_random.restype = None
        return vscf_recipient_cipher_use_random(ctx, random)

    def vscf_recipient_cipher_use_encryption_cipher(self, ctx, encryption_cipher):
        vscf_recipient_cipher_use_encryption_cipher = self._lib.vscf_recipient_cipher_use_encryption_cipher
        vscf_recipient_cipher_use_encryption_cipher.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_impl_t)]
        vscf_recipient_cipher_use_encryption_cipher.restype = None
        return vscf_recipient_cipher_use_encryption_cipher(ctx, encryption_cipher)

    def vscf_recipient_cipher_use_encryption_padding(self, ctx, encryption_padding):
        vscf_recipient_cipher_use_encryption_padding = self._lib.vscf_recipient_cipher_use_encryption_padding
        vscf_recipient_cipher_use_encryption_padding.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_impl_t)]
        vscf_recipient_cipher_use_encryption_padding.restype = None
        return vscf_recipient_cipher_use_encryption_padding(ctx, encryption_padding)

    def vscf_recipient_cipher_use_padding_params(self, ctx, padding_params):
        vscf_recipient_cipher_use_padding_params = self._lib.vscf_recipient_cipher_use_padding_params
        vscf_recipient_cipher_use_padding_params.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_padding_params_t)]
        vscf_recipient_cipher_use_padding_params.restype = None
        return vscf_recipient_cipher_use_padding_params(ctx, padding_params)

    def vscf_recipient_cipher_use_signer_hash(self, ctx, signer_hash):
        vscf_recipient_cipher_use_signer_hash = self._lib.vscf_recipient_cipher_use_signer_hash
        vscf_recipient_cipher_use_signer_hash.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_impl_t)]
        vscf_recipient_cipher_use_signer_hash.restype = None
        return vscf_recipient_cipher_use_signer_hash(ctx, signer_hash)

    def vscf_recipient_cipher_has_key_recipient(self, ctx, recipient_id):
        """Return true if a key recipient with a given id has been added.
        Note, operation has O(N) time complexity."""
        vscf_recipient_cipher_has_key_recipient = self._lib.vscf_recipient_cipher_has_key_recipient
        vscf_recipient_cipher_has_key_recipient.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t]
        vscf_recipient_cipher_has_key_recipient.restype = c_bool
        return vscf_recipient_cipher_has_key_recipient(ctx, recipient_id)

    def vscf_recipient_cipher_add_key_recipient(self, ctx, recipient_id, public_key):
        """Add recipient defined with id and public key."""
        vscf_recipient_cipher_add_key_recipient = self._lib.vscf_recipient_cipher_add_key_recipient
        vscf_recipient_cipher_add_key_recipient.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vscf_impl_t)]
        vscf_recipient_cipher_add_key_recipient.restype = None
        return vscf_recipient_cipher_add_key_recipient(ctx, recipient_id, public_key)

    def vscf_recipient_cipher_clear_recipients(self, ctx):
        """Remove all recipients."""
        vscf_recipient_cipher_clear_recipients = self._lib.vscf_recipient_cipher_clear_recipients
        vscf_recipient_cipher_clear_recipients.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_clear_recipients.restype = None
        return vscf_recipient_cipher_clear_recipients(ctx)

    def vscf_recipient_cipher_add_signer(self, ctx, signer_id, private_key):
        """Add identifier and private key to sign initial plain text.
        Return error if the private key can not sign."""
        vscf_recipient_cipher_add_signer = self._lib.vscf_recipient_cipher_add_signer
        vscf_recipient_cipher_add_signer.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vscf_impl_t)]
        vscf_recipient_cipher_add_signer.restype = c_int
        return vscf_recipient_cipher_add_signer(ctx, signer_id, private_key)

    def vscf_recipient_cipher_clear_signers(self, ctx):
        """Remove all signers."""
        vscf_recipient_cipher_clear_signers = self._lib.vscf_recipient_cipher_clear_signers
        vscf_recipient_cipher_clear_signers.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_clear_signers.restype = None
        return vscf_recipient_cipher_clear_signers(ctx)

    def vscf_recipient_cipher_custom_params(self, ctx):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it."""
        vscf_recipient_cipher_custom_params = self._lib.vscf_recipient_cipher_custom_params
        vscf_recipient_cipher_custom_params.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_custom_params.restype = POINTER(vscf_message_info_custom_params_t)
        return vscf_recipient_cipher_custom_params(ctx)

    def vscf_recipient_cipher_start_encryption(self, ctx):
        """Start encryption process."""
        vscf_recipient_cipher_start_encryption = self._lib.vscf_recipient_cipher_start_encryption
        vscf_recipient_cipher_start_encryption.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_start_encryption.restype = c_int
        return vscf_recipient_cipher_start_encryption(ctx)

    def vscf_recipient_cipher_start_signed_encryption(self, ctx, data_size):
        """Start encryption process with known plain text size.

        Precondition: At least one signer should be added.
        Note, store message info footer as well."""
        vscf_recipient_cipher_start_signed_encryption = self._lib.vscf_recipient_cipher_start_signed_encryption
        vscf_recipient_cipher_start_signed_encryption.argtypes = [POINTER(vscf_recipient_cipher_t), c_size_t]
        vscf_recipient_cipher_start_signed_encryption.restype = c_int
        return vscf_recipient_cipher_start_signed_encryption(ctx, data_size)

    def vscf_recipient_cipher_message_info_len(self, ctx):
        """Return buffer length required to hold message info returned by the
        "pack message info" method.
        Precondition: all recipients and custom parameters should be set."""
        vscf_recipient_cipher_message_info_len = self._lib.vscf_recipient_cipher_message_info_len
        vscf_recipient_cipher_message_info_len.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_message_info_len.restype = c_size_t
        return vscf_recipient_cipher_message_info_len(ctx)

    def vscf_recipient_cipher_pack_message_info(self, ctx, message_info):
        """Return serialized message info to the buffer.

        Precondition: this method should be called after "start encryption".
        Precondition: this method should be called before "finish encryption".

        Note, store message info to use it for decryption process,
        or place it at the encrypted data beginning (embedding).

        Return message info - recipients public information,
        algorithm information, etc."""
        vscf_recipient_cipher_pack_message_info = self._lib.vscf_recipient_cipher_pack_message_info
        vscf_recipient_cipher_pack_message_info.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_pack_message_info.restype = None
        return vscf_recipient_cipher_pack_message_info(ctx, message_info)

    def vscf_recipient_cipher_encryption_out_len(self, ctx, data_len):
        """Return buffer length required to hold output of the method
        "process encryption" and method "finish" during encryption."""
        vscf_recipient_cipher_encryption_out_len = self._lib.vscf_recipient_cipher_encryption_out_len
        vscf_recipient_cipher_encryption_out_len.argtypes = [POINTER(vscf_recipient_cipher_t), c_size_t]
        vscf_recipient_cipher_encryption_out_len.restype = c_size_t
        return vscf_recipient_cipher_encryption_out_len(ctx, data_len)

    def vscf_recipient_cipher_process_encryption(self, ctx, data, out):
        """Process encryption of a new portion of data."""
        vscf_recipient_cipher_process_encryption = self._lib.vscf_recipient_cipher_process_encryption
        vscf_recipient_cipher_process_encryption.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_process_encryption.restype = c_int
        return vscf_recipient_cipher_process_encryption(ctx, data, out)

    def vscf_recipient_cipher_finish_encryption(self, ctx, out):
        """Accomplish encryption."""
        vscf_recipient_cipher_finish_encryption = self._lib.vscf_recipient_cipher_finish_encryption
        vscf_recipient_cipher_finish_encryption.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_finish_encryption.restype = c_int
        return vscf_recipient_cipher_finish_encryption(ctx, out)

    def vscf_recipient_cipher_start_decryption_with_key(self, ctx, recipient_id, private_key, message_info):
        """Initiate decryption process with a recipient private key.
        Message Info can be empty if it was embedded to encrypted data."""
        vscf_recipient_cipher_start_decryption_with_key = self._lib.vscf_recipient_cipher_start_decryption_with_key
        vscf_recipient_cipher_start_decryption_with_key.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vscf_impl_t), vsc_data_t]
        vscf_recipient_cipher_start_decryption_with_key.restype = c_int
        return vscf_recipient_cipher_start_decryption_with_key(ctx, recipient_id, private_key, message_info)

    def vscf_recipient_cipher_start_verified_decryption_with_key(self, ctx, recipient_id, private_key, message_info, message_info_footer):
        """Initiate decryption process with a recipient private key.
        Message Info can be empty if it was embedded to encrypted data.
        Message Info footer can be empty if it was embedded to encrypted data.
        If footer was embedded, method "start decryption with key" can be used."""
        vscf_recipient_cipher_start_verified_decryption_with_key = self._lib.vscf_recipient_cipher_start_verified_decryption_with_key
        vscf_recipient_cipher_start_verified_decryption_with_key.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vscf_impl_t), vsc_data_t, vsc_data_t]
        vscf_recipient_cipher_start_verified_decryption_with_key.restype = c_int
        return vscf_recipient_cipher_start_verified_decryption_with_key(ctx, recipient_id, private_key, message_info, message_info_footer)

    def vscf_recipient_cipher_decryption_out_len(self, ctx, data_len):
        """Return buffer length required to hold output of the method
        "process decryption" and method "finish" during decryption."""
        vscf_recipient_cipher_decryption_out_len = self._lib.vscf_recipient_cipher_decryption_out_len
        vscf_recipient_cipher_decryption_out_len.argtypes = [POINTER(vscf_recipient_cipher_t), c_size_t]
        vscf_recipient_cipher_decryption_out_len.restype = c_size_t
        return vscf_recipient_cipher_decryption_out_len(ctx, data_len)

    def vscf_recipient_cipher_process_decryption(self, ctx, data, out):
        """Process with a new portion of data.
        Return error if data can not be encrypted or decrypted."""
        vscf_recipient_cipher_process_decryption = self._lib.vscf_recipient_cipher_process_decryption
        vscf_recipient_cipher_process_decryption.argtypes = [POINTER(vscf_recipient_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_process_decryption.restype = c_int
        return vscf_recipient_cipher_process_decryption(ctx, data, out)

    def vscf_recipient_cipher_finish_decryption(self, ctx, out):
        """Accomplish decryption."""
        vscf_recipient_cipher_finish_decryption = self._lib.vscf_recipient_cipher_finish_decryption
        vscf_recipient_cipher_finish_decryption.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_finish_decryption.restype = c_int
        return vscf_recipient_cipher_finish_decryption(ctx, out)

    def vscf_recipient_cipher_is_data_signed(self, ctx):
        """Return true if data was signed by a sender.

        Precondition: this method should be called after "finish decryption"."""
        vscf_recipient_cipher_is_data_signed = self._lib.vscf_recipient_cipher_is_data_signed
        vscf_recipient_cipher_is_data_signed.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_is_data_signed.restype = c_bool
        return vscf_recipient_cipher_is_data_signed(ctx)

    def vscf_recipient_cipher_signer_infos(self, ctx):
        """Return information about signers that sign data.

        Precondition: this method should be called after "finish decryption".
        Precondition: method "is data signed" returns true."""
        vscf_recipient_cipher_signer_infos = self._lib.vscf_recipient_cipher_signer_infos
        vscf_recipient_cipher_signer_infos.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_signer_infos.restype = POINTER(vscf_signer_info_list_t)
        return vscf_recipient_cipher_signer_infos(ctx)

    def vscf_recipient_cipher_verify_signer_info(self, ctx, signer_info, public_key):
        """Verify given cipher info."""
        vscf_recipient_cipher_verify_signer_info = self._lib.vscf_recipient_cipher_verify_signer_info
        vscf_recipient_cipher_verify_signer_info.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vscf_signer_info_t), POINTER(vscf_impl_t)]
        vscf_recipient_cipher_verify_signer_info.restype = c_bool
        return vscf_recipient_cipher_verify_signer_info(ctx, signer_info, public_key)

    def vscf_recipient_cipher_message_info_footer_len(self, ctx):
        """Return buffer length required to hold message footer returned by the
        "pack message footer" method.

        Precondition: this method should be called after "finish encryption"."""
        vscf_recipient_cipher_message_info_footer_len = self._lib.vscf_recipient_cipher_message_info_footer_len
        vscf_recipient_cipher_message_info_footer_len.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_message_info_footer_len.restype = c_size_t
        return vscf_recipient_cipher_message_info_footer_len(ctx)

    def vscf_recipient_cipher_pack_message_info_footer(self, ctx, out):
        """Return serialized message info footer to the buffer.

        Precondition: this method should be called after "finish encryption".

        Note, store message info to use it for verified decryption process,
        or place it at the encrypted data ending (embedding).

        Return message info footer - signers public information, etc."""
        vscf_recipient_cipher_pack_message_info_footer = self._lib.vscf_recipient_cipher_pack_message_info_footer
        vscf_recipient_cipher_pack_message_info_footer.argtypes = [POINTER(vscf_recipient_cipher_t), POINTER(vsc_buffer_t)]
        vscf_recipient_cipher_pack_message_info_footer.restype = c_int
        return vscf_recipient_cipher_pack_message_info_footer(ctx, out)

    def vscf_recipient_cipher_shallow_copy(self, ctx):
        vscf_recipient_cipher_shallow_copy = self._lib.vscf_recipient_cipher_shallow_copy
        vscf_recipient_cipher_shallow_copy.argtypes = [POINTER(vscf_recipient_cipher_t)]
        vscf_recipient_cipher_shallow_copy.restype = POINTER(vscf_recipient_cipher_t)
        return vscf_recipient_cipher_shallow_copy(ctx)
