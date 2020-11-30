//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  Contains information about the group and performs encryption and decryption operations.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_GROUP_H_INCLUDED
#define VSSQ_MESSENGER_GROUP_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_auth.h"
#include "vssq_messenger_user.h"
#include "vssq_status.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_str_buffer.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Public integral constants.
//
enum {
    vssq_messenger_group_SESSION_ID_LEN = 32
};

//
//  Handle 'messenger group' context.
//
#ifndef VSSQ_MESSENGER_GROUP_T_DEFINED
#define VSSQ_MESSENGER_GROUP_T_DEFINED
    typedef struct vssq_messenger_group_t vssq_messenger_group_t;
#endif // VSSQ_MESSENGER_GROUP_T_DEFINED

//
//  Return size of 'vssq_messenger_group_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_init(vssq_messenger_group_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_cleanup(vssq_messenger_group_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_group_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_delete(const vssq_messenger_group_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_destroy(vssq_messenger_group_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_group_shallow_copy(vssq_messenger_group_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_group_t *
vssq_messenger_group_shallow_copy_const(const vssq_messenger_group_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_use_random(vssq_messenger_group_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_take_random(vssq_messenger_group_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_group_release_random(vssq_messenger_group_t *self);

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_use_auth(vssq_messenger_group_t *self, vssq_messenger_auth_t *auth);

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_take_auth(vssq_messenger_group_t *self, vssq_messenger_auth_t *auth);

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_group_release_auth(vssq_messenger_group_t *self);

//
//  Return user info of the group owner.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_group_owner(const vssq_messenger_group_t *self);

//
//  Delete group.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_remove(vssq_messenger_group_t *self) VSSQ_NODISCARD;

//
//  Return a buffer length enough to hold an encrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_encrypted_message_len(const vssq_messenger_group_t *self, size_t plaintext_len);

//
//  Encrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_encrypt_message(const vssq_messenger_group_t *self, vsc_str_t plaintext,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return a buffer length enough to hold a decrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_decrypted_message_len(const vssq_messenger_group_t *self, size_t encrypted_len);

//
//  Decrypt a group message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_decrypt_message(const vssq_messenger_group_t *self, vsc_data_t encrypted_message,
        const vssq_messenger_user_t *from_user, vsc_str_buffer_t *out) VSSQ_NODISCARD;

//
//  Check if current user can modify a group.
//
VSSQ_PUBLIC bool
vssq_messenger_group_check_permission_modify(const vssq_messenger_group_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_GROUP_H_INCLUDED
//  @end
