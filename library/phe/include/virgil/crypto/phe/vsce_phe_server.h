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
//  Class for server-side PHE crypto operations.
//  This class is thread-safe in case if VSCE_MULTI_THREAD defined
// --------------------------------------------------------------------------

#ifndef VSCE_PHE_SERVER_H_INCLUDED
#define VSCE_PHE_SERVER_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_status.h"

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if !VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
#endif

#if VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'phe server' context.
//
typedef struct vsce_phe_server_t vsce_phe_server_t;

//
//  Return size of 'vsce_phe_server_t'.
//
VSCE_PUBLIC size_t
vsce_phe_server_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_server_init(vsce_phe_server_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_server_cleanup(vsce_phe_server_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_server_delete(vsce_phe_server_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_server_new ()'.
//
VSCE_PUBLIC void
vsce_phe_server_destroy(vsce_phe_server_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_shallow_copy(vsce_phe_server_t *self);

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_server_use_random(vsce_phe_server_t *self, vscf_impl_t *random);

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_server_take_random(vsce_phe_server_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_server_release_random(vsce_phe_server_t *self);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_server_use_operation_random(vsce_phe_server_t *self, vscf_impl_t *operation_random);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_server_take_operation_random(vsce_phe_server_t *self, vscf_impl_t *operation_random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_server_release_operation_random(vsce_phe_server_t *self);

//
//  Generates new NIST P-256 server key pair for some client
//
VSCE_PUBLIC vsce_status_t
vsce_phe_server_generate_server_key_pair(vsce_phe_server_t *self, vsc_buffer_t *server_private_key,
        vsc_buffer_t *server_public_key);

//
//  Buffer size needed to fit EnrollmentResponse
//
VSCE_PUBLIC size_t
vsce_phe_server_enrollment_response_len(vsce_phe_server_t *self);

//
//  Generates a new random enrollment and proof for a new user
//
VSCE_PUBLIC vsce_status_t
vsce_phe_server_get_enrollment(vsce_phe_server_t *self, vsc_data_t server_private_key, vsc_data_t server_public_key,
        vsc_buffer_t *enrollment_response);

//
//  Buffer size needed to fit VerifyPasswordResponse
//
VSCE_PUBLIC size_t
vsce_phe_server_verify_password_response_len(vsce_phe_server_t *self);

//
//  Verifies existing user's password and generates response with proof
//
VSCE_PUBLIC vsce_status_t
vsce_phe_server_verify_password(vsce_phe_server_t *self, vsc_data_t server_private_key, vsc_data_t server_public_key,
        vsc_data_t verify_password_request, vsc_buffer_t *verify_password_response);

//
//  Buffer size needed to fit UpdateToken
//
VSCE_PUBLIC size_t
vsce_phe_server_update_token_len(vsce_phe_server_t *self);

//
//  Updates server's private and public keys and issues an update token for use on client's side
//
VSCE_PUBLIC vsce_status_t
vsce_phe_server_rotate_keys(vsce_phe_server_t *self, vsc_data_t server_private_key,
        vsc_buffer_t *new_server_private_key, vsc_buffer_t *new_server_public_key, vsc_buffer_t *update_token);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_SERVER_H_INCLUDED
//  @end
