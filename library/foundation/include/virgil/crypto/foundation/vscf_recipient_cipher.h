//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This class provides hybrid encryption algorithm that combines symmetric
//  cipher for data encryption and asymmetric cipher and password based
//  cipher for symmetric key encryption.
// --------------------------------------------------------------------------

#ifndef VSCF_RECIPIENT_CIPHER_H_INCLUDED
#define VSCF_RECIPIENT_CIPHER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_padding_params.h"
#include "vscf_message_info_custom_params.h"
#include "vscf_signer_info_list.h"
#include "vscf_signer_info.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'recipient cipher' context.
//
typedef struct vscf_recipient_cipher_t vscf_recipient_cipher_t;

//
//  Return size of 'vscf_recipient_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_recipient_cipher_init(vscf_recipient_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_recipient_cipher_cleanup(vscf_recipient_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_recipient_cipher_t *
vscf_recipient_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_recipient_cipher_delete(vscf_recipient_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_recipient_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_destroy(vscf_recipient_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_recipient_cipher_t *
vscf_recipient_cipher_shallow_copy(vscf_recipient_cipher_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_random(vscf_recipient_cipher_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_random(vscf_recipient_cipher_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_random(vscf_recipient_cipher_t *self);

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_encryption_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_cipher);

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_encryption_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_cipher);

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_encryption_cipher(vscf_recipient_cipher_t *self);

//
//  Setup dependency to the interface 'padding' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_encryption_padding(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_padding);

//
//  Setup dependency to the interface 'padding' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_encryption_padding(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_padding);

//
//  Release dependency to the interface 'padding'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_encryption_padding(vscf_recipient_cipher_t *self);

//
//  Setup dependency to the class 'padding params' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_padding_params(vscf_recipient_cipher_t *self, vscf_padding_params_t *padding_params);

//
//  Setup dependency to the class 'padding params' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_padding_params(vscf_recipient_cipher_t *self, vscf_padding_params_t *padding_params);

//
//  Release dependency to the class 'padding params'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_padding_params(vscf_recipient_cipher_t *self);

//
//  Setup dependency to the interface 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_signer_hash(vscf_recipient_cipher_t *self, vscf_impl_t *signer_hash);

//
//  Setup dependency to the interface 'hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_signer_hash(vscf_recipient_cipher_t *self, vscf_impl_t *signer_hash);

//
//  Release dependency to the interface 'hash'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_signer_hash(vscf_recipient_cipher_t *self);

//
//  Return true if a key recipient with a given id has been added.
//  Note, operation has O(N) time complexity.
//
VSCF_PUBLIC bool
vscf_recipient_cipher_has_key_recipient(const vscf_recipient_cipher_t *self, vsc_data_t recipient_id);

//
//  Add recipient defined with id and public key.
//
VSCF_PUBLIC void
vscf_recipient_cipher_add_key_recipient(vscf_recipient_cipher_t *self, vsc_data_t recipient_id,
        vscf_impl_t *public_key);

//
//  Remove all recipients.
//
VSCF_PUBLIC void
vscf_recipient_cipher_clear_recipients(vscf_recipient_cipher_t *self);

//
//  Add identifier and private key to sign initial plain text.
//  Return error if the private key can not sign.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_add_signer(vscf_recipient_cipher_t *self, vsc_data_t signer_id,
        vscf_impl_t *private_key) VSCF_NODISCARD;

//
//  Remove all signers.
//
VSCF_PUBLIC void
vscf_recipient_cipher_clear_signers(vscf_recipient_cipher_t *self);

//
//  Provide access to the custom params object.
//  The returned object can be used to add custom params or read it.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_recipient_cipher_custom_params(vscf_recipient_cipher_t *self);

//
//  Start encryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_encryption(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Start encryption process with known plain text size.
//
//  Precondition: At least one signer should be added.
//  Note, store message info footer as well.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_signed_encryption(vscf_recipient_cipher_t *self, size_t data_size) VSCF_NODISCARD;

//
//  Return buffer length required to hold message info returned by the
//  "pack message info" method.
//  Precondition: all recipients and custom parameters should be set.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_message_info_len(const vscf_recipient_cipher_t *self);

//
//  Return serialized message info to the buffer.
//
//  Precondition: this method should be called after "start encryption".
//  Precondition: this method should be called before "finish encryption".
//
//  Note, store message info to use it for decryption process,
//  or place it at the encrypted data beginning (embedding).
//
//  Return message info - recipients public information,
//  algorithm information, etc.
//
VSCF_PUBLIC void
vscf_recipient_cipher_pack_message_info(vscf_recipient_cipher_t *self, vsc_buffer_t *message_info);

//
//  Return buffer length required to hold output of the method
//  "process encryption" and method "finish" during encryption.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_encryption_out_len(vscf_recipient_cipher_t *self, size_t data_len);

//
//  Process encryption of a new portion of data.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_process_encryption(vscf_recipient_cipher_t *self, vsc_data_t data,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Accomplish encryption.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_finish_encryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Initiate decryption process with a recipient private key.
//  Message Info can be empty if it was embedded to encrypted data.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_decryption_with_key(vscf_recipient_cipher_t *self, vsc_data_t recipient_id,
        vscf_impl_t *private_key, vsc_data_t message_info) VSCF_NODISCARD;

//
//  Initiate decryption process with a recipient private key.
//  Message Info can be empty if it was embedded to encrypted data.
//  Message Info footer can be empty if it was embedded to encrypted data.
//  If footer was embedded, method "start decryption with key" can be used.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_verified_decryption_with_key(vscf_recipient_cipher_t *self, vsc_data_t recipient_id,
        vscf_impl_t *private_key, vsc_data_t message_info, vsc_data_t message_info_footer) VSCF_NODISCARD;

//
//  Return buffer length required to hold output of the method
//  "process decryption" and method "finish" during decryption.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_decryption_out_len(vscf_recipient_cipher_t *self, size_t data_len);

//
//  Process with a new portion of data.
//  Return error if data can not be encrypted or decrypted.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_process_decryption(vscf_recipient_cipher_t *self, vsc_data_t data,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Accomplish decryption.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_finish_decryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return true if data was signed by a sender.
//
//  Precondition: this method should be called after "finish decryption".
//
VSCF_PUBLIC bool
vscf_recipient_cipher_is_data_signed(const vscf_recipient_cipher_t *self);

//
//  Return information about signers that sign data.
//
//  Precondition: this method should be called after "finish decryption".
//  Precondition: method "is data signed" returns true.
//
VSCF_PUBLIC const vscf_signer_info_list_t *
vscf_recipient_cipher_signer_infos(const vscf_recipient_cipher_t *self);

//
//  Verify given cipher info.
//
VSCF_PUBLIC bool
vscf_recipient_cipher_verify_signer_info(vscf_recipient_cipher_t *self, const vscf_signer_info_t *signer_info,
        const vscf_impl_t *public_key);

//
//  Return buffer length required to hold message footer returned by the
//  "pack message footer" method.
//
//  Precondition: this method should be called after "finish encryption".
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_message_info_footer_len(const vscf_recipient_cipher_t *self);

//
//  Return serialized message info footer to the buffer.
//
//  Precondition: this method should be called after "finish encryption".
//
//  Note, store message info to use it for verified decryption process,
//  or place it at the encrypted data ending (embedding).
//
//  Return message info footer - signers public information, etc.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_pack_message_info_footer(vscf_recipient_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RECIPIENT_CIPHER_H_INCLUDED
//  @end
