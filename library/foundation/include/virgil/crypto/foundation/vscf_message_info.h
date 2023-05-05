//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Handle information about an encrypted message and algorithms
//  that was used for encryption.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_H_INCLUDED
#define VSCF_MESSAGE_INFO_H_INCLUDED

#include "vscf_library.h"
#include "vscf_key_recipient_info.h"
#include "vscf_password_recipient_info.h"
#include "vscf_key_recipient_info_list.h"
#include "vscf_password_recipient_info_list.h"
#include "vscf_message_info_custom_params.h"
#include "vscf_footer_info.h"
#include "vscf_impl.h"

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
//  Handle 'message info' context.
//
typedef struct vscf_message_info_t vscf_message_info_t;

//
//  Return size of 'vscf_message_info_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_init(vscf_message_info_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_cleanup(vscf_message_info_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_t *
vscf_message_info_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_info_delete(vscf_message_info_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_destroy(vscf_message_info_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_t *
vscf_message_info_shallow_copy(vscf_message_info_t *self);

//
//  Add recipient that is defined by Public Key.
//
VSCF_PRIVATE void
vscf_message_info_add_key_recipient(vscf_message_info_t *self, vscf_key_recipient_info_t **key_recipient_ref);

//
//  Add recipient that is defined by password.
//
VSCF_PRIVATE void
vscf_message_info_add_password_recipient(vscf_message_info_t *self,
        vscf_password_recipient_info_t **password_recipient_ref);

//
//  Set information about algorithm that was used for data encryption.
//
VSCF_PRIVATE void
vscf_message_info_set_data_encryption_alg_info(vscf_message_info_t *self, vscf_impl_t **data_encryption_alg_info_ref);

//
//  Return information about algorithm that was used for the data encryption.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_message_info_data_encryption_alg_info(const vscf_message_info_t *self);

//
//  Return list with a "key recipient info" elements.
//
VSCF_PUBLIC const vscf_key_recipient_info_list_t *
vscf_message_info_key_recipient_info_list(const vscf_message_info_t *self);

//
//  Return list with a "key recipient info" elements.
//
VSCF_PRIVATE vscf_key_recipient_info_list_t *
vscf_message_info_key_recipient_info_list_modifiable(vscf_message_info_t *self);

//
//  Return list with a "password recipient info" elements.
//
VSCF_PUBLIC const vscf_password_recipient_info_list_t *
vscf_message_info_password_recipient_info_list(const vscf_message_info_t *self);

//
//  Remove all recipients.
//
VSCF_PRIVATE void
vscf_message_info_clear_recipients(vscf_message_info_t *self);

//
//  Setup custom params.
//
VSCF_PRIVATE void
vscf_message_info_set_custom_params(vscf_message_info_t *self, vscf_message_info_custom_params_t **custom_params_ref);

//
//  Return true if message info contains at least one custom param.
//
VSCF_PUBLIC bool
vscf_message_info_has_custom_params(const vscf_message_info_t *self);

//
//  Provide access to the custom params object.
//  The returned object can be used to add custom params or read it.
//  If custom params object was not set then new empty object is created.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_message_info_custom_params(vscf_message_info_t *self);

//
//  Return true if cipher kdf alg info exists.
//
VSCF_PUBLIC bool
vscf_message_info_has_cipher_kdf_alg_info(const vscf_message_info_t *self);

//
//  Setup cipher kdf alg info.
//
VSCF_PRIVATE void
vscf_message_info_set_cipher_kdf_alg_info(vscf_message_info_t *self, vscf_impl_t **cipher_kdf_alg_info_ref);

//
//  Return cipher kdf alg info.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_message_info_cipher_kdf_alg_info(const vscf_message_info_t *self);

//
//  Remove cipher kdf alg info.
//
VSCF_PRIVATE void
vscf_message_info_remove_cipher_kdf_alg_info(vscf_message_info_t *self);

//
//  Return true if cipher padding alg info exists.
//
VSCF_PUBLIC bool
vscf_message_info_has_cipher_padding_alg_info(const vscf_message_info_t *self);

//
//  Setup cipher padding alg info.
//
VSCF_PRIVATE void
vscf_message_info_set_cipher_padding_alg_info(vscf_message_info_t *self, vscf_impl_t **cipher_padding_alg_info_ref);

//
//  Return cipher padding alg info.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_message_info_cipher_padding_alg_info(const vscf_message_info_t *self);

//
//  Remove cipher padding alg info.
//
VSCF_PRIVATE void
vscf_message_info_remove_cipher_padding_alg_info(vscf_message_info_t *self);

//
//  Return true if footer info exists.
//
VSCF_PUBLIC bool
vscf_message_info_has_footer_info(const vscf_message_info_t *self);

//
//  Setup footer info.
//
VSCF_PRIVATE void
vscf_message_info_set_footer_info(vscf_message_info_t *self, vscf_footer_info_t **footer_info_ref);

//
//  Return footer info.
//
VSCF_PUBLIC const vscf_footer_info_t *
vscf_message_info_footer_info(const vscf_message_info_t *self);

//
//  Return mutable footer info.
//
VSCF_PRIVATE vscf_footer_info_t *
vscf_message_info_footer_info_m(vscf_message_info_t *self);

//
//  Remove footer info.
//
VSCF_PRIVATE void
vscf_message_info_remove_footer_info(vscf_message_info_t *self);

//
//  Remove all infos.
//
VSCF_PUBLIC void
vscf_message_info_clear(vscf_message_info_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_H_INCLUDED
//  @end
