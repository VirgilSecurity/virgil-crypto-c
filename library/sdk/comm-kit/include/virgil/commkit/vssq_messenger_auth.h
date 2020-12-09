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
//  Provides access to the messenger authentication endpoints.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_AUTH_H_INCLUDED
#define VSSQ_MESSENGER_AUTH_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_config.h"
#include "vssq_status.h"
#include "vssq_messenger_creds.h"
#include "vssq_error.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
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
//  Handle 'messenger auth' context.
//
#ifndef VSSQ_MESSENGER_AUTH_T_DEFINED
#define VSSQ_MESSENGER_AUTH_T_DEFINED
    typedef struct vssq_messenger_auth_t vssq_messenger_auth_t;
#endif // VSSQ_MESSENGER_AUTH_T_DEFINED

//
//  Return size of 'vssq_messenger_auth_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_auth_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init(vssq_messenger_auth_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_auth_cleanup(vssq_messenger_auth_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new(void);

//
//  Perform initialization of pre-allocated context.
//  Initialze messenger with a custom config.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init_with_config(vssq_messenger_auth_t *self, const vssq_messenger_config_t *config);

//
//  Allocate class context and perform it's initialization.
//  Initialze messenger with a custom config.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new_with_config(const vssq_messenger_config_t *config);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_auth_delete(const vssq_messenger_auth_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_auth_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_destroy(vssq_messenger_auth_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy(vssq_messenger_auth_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy_const(const vssq_messenger_auth_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_auth_use_random(vssq_messenger_auth_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_auth_take_random(vssq_messenger_auth_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_release_random(vssq_messenger_auth_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_setup_defaults(vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Register a new user with a give name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_register(vssq_messenger_auth_t *self, vsc_str_t username) VSSQ_NODISCARD;

//
//  Register a new user with a give name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_authenticate(vssq_messenger_auth_t *self, const vssq_messenger_creds_t *creds) VSSQ_NODISCARD;

//
//  Return true if user credentials are defined.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_creds(const vssq_messenger_auth_t *self);

//
//  Return user credentials.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_auth_creds(const vssq_messenger_auth_t *self);

//
//  Check whether current credentials were backed up.
//
//  Prerequisites: credentials must be set.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_backup_creds(const vssq_messenger_auth_t *self, vssq_error_t *error);

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: credentials must be set.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_backup_creds(const vssq_messenger_auth_t *self, vsc_str_t pwd) VSSQ_NODISCARD;

//
//  Pull an encrypted user credentials from the Keyknox and decrypt it.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_restore_creds(vssq_messenger_auth_t *self, vsc_str_t username, vsc_str_t pwd) VSSQ_NODISCARD;

//
//  Return JWT length if it exists and not expired, or max - otherwise.
//
VSSQ_PUBLIC size_t
vssq_messenger_auth_base_token_len(const vssq_messenger_auth_t *self);

//
//  Get JWT to use with Messenger Backend based on the credentials.
//
//  Prerequisites: credentials must be set.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_base_token(const vssq_messenger_auth_t *self, vsc_str_buffer_t *token) VSSQ_NODISCARD;

//
//  Return Ejabberd token length if token exists and not expired, or max - otherwise.
//
VSSQ_PUBLIC size_t
vssq_messenger_auth_ejabberd_token_len(const vssq_messenger_auth_t *self);

//
//  Return JWT to aceess ejabberd server.
//
//  Format: https://docs.ejabberd.im/admin/configuration/authentication/#jwt-authentication
//
//  Prerequisites: credentials must be set.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_ejabberd_token(const vssq_messenger_auth_t *self, vsc_str_buffer_t *token) VSSQ_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_AUTH_H_INCLUDED
//  @end