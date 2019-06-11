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
//  Handle information about recipient that is defined by a Public Key.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_RECIPIENT_INFO_H_INCLUDED
#define VSCF_KEY_RECIPIENT_INFO_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
//  Handle 'key recipient info' context.
//
typedef struct vscf_key_recipient_info_t vscf_key_recipient_info_t;

//
//  Return size of 'vscf_key_recipient_info_t'.
//
VSCF_PUBLIC size_t
vscf_key_recipient_info_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_recipient_info_init(vscf_key_recipient_info_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_recipient_info_cleanup(vscf_key_recipient_info_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create object and define all properties.
//
VSCF_PUBLIC void
vscf_key_recipient_info_init_with_members(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        vscf_impl_t **key_encryption_algorithm_ref, vsc_data_t encrypted_key);

//
//  Allocate class context and perform it's initialization.
//  Create object and define all properties.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new_with_members(vsc_data_t recipient_id, vscf_impl_t **key_encryption_algorithm_ref,
        vsc_data_t encrypted_key);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_recipient_info_delete(vscf_key_recipient_info_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_recipient_info_new ()'.
//
VSCF_PUBLIC void
vscf_key_recipient_info_destroy(vscf_key_recipient_info_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_shallow_copy(vscf_key_recipient_info_t *self);

//
//  Return recipient identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_key_recipient_info_recipient_id(const vscf_key_recipient_info_t *self);

//
//  Return algorithm information that was used for encryption
//  a data encryption key.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_key_recipient_info_key_encryption_algorithm(const vscf_key_recipient_info_t *self);

//
//  Return an encrypted data encryption key.
//
VSCF_PUBLIC vsc_data_t
vscf_key_recipient_info_encrypted_key(const vscf_key_recipient_info_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_RECIPIENT_INFO_H_INCLUDED
//  @end
