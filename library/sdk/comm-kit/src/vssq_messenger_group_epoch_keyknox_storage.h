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
//  Provides read/write operations of the Group Epochs to/from remote
//  secure storage (Keyknox).
//
//  Note, a group credentials are unique to the epoch.
//  Note, a group credentials are encrypted for all group participants.
//
//  Keyknox internal structure:
//      {
//          "root" : "group-sessions",
//          "path" : "<session-id>",
//          "key"  : "<epoch>"
//      }
//
//      * <session-id> - HEX(sha512(session-id):0..32)
//      * <epoch>      - integer counter, incrementing epoch means group key rotatation
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_H_INCLUDED
#define VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_auth.h"
#include "vssq_messenger_group_epoch.h"
#include "vssq_messenger_user_list.h"
#include "vssq_status.h"
#include "vssq_messenger_user.h"
#include "vssq_error.h"
#include "vssq_messenger_group_epoch_list.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_number_list.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str_buffer.h>
#   include <VSCCommon/vsc_data.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSC/vssc_number_list.h>
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
    //
    //  Maximum length for an unsigned number string representation including a null-termination symbol.
    //  Note, NUM_CHARS(2^64) = NUM_CHARS(18446744073709551616) = 20
    //
    vssq_messenger_group_epoch_keyknox_storage_NUM_STR_LEN_MAX = 21
};

//
//  Handle 'messenger group epoch keyknox storage' context.
//
#ifndef VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_T_DEFINED
#define VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_T_DEFINED
    typedef struct vssq_messenger_group_epoch_keyknox_storage_t vssq_messenger_group_epoch_keyknox_storage_t;
#endif // VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_T_DEFINED

//
//  Return size of 'vssq_messenger_group_epoch_keyknox_storage_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_keyknox_storage_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_init(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_cleanup(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_delete(const vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_epoch_keyknox_storage_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_destroy(vssq_messenger_group_epoch_keyknox_storage_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_shallow_copy(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_group_epoch_keyknox_storage_t *
vssq_messenger_group_epoch_keyknox_storage_shallow_copy_const(
        const vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_use_random(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_take_random(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_release_random(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_use_auth(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vssq_messenger_auth_t *auth);

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_take_auth(vssq_messenger_group_epoch_keyknox_storage_t *self,
        vssq_messenger_auth_t *auth);

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_keyknox_storage_release_auth(vssq_messenger_group_epoch_keyknox_storage_t *self);

//
//  Encrypt given group epoch for all participants and for self and push it to the Keyknox.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_write(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_group_epoch_t *group_epoch,
        const vssq_messenger_user_list_t *participants) VSSQ_NODISCARD;

//
//  Pull requested epoch from the Keyknox, decrypt it and verify owner's signature.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_keyknox_storage_read(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, size_t group_epoch_num, const vssq_messenger_user_t *owner, vssq_error_t *error);

//
//  Pull all epochs from the Keyknox, decrypt it and verify owner's signature.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_list_t *
vssq_messenger_group_epoch_keyknox_storage_read_all(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_user_t *owner, vssq_error_t *error);

//
//  Remove all epochs from the Keyknox.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_epoch_keyknox_storage_remove_all(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id) VSSQ_NODISCARD;

//
//  Pull available epoch serial numbers.
//
VSSQ_PUBLIC vssc_number_list_t *
vssq_messenger_group_epoch_keyknox_storage_read_epoch_nums(const vssq_messenger_group_epoch_keyknox_storage_t *self,
        vsc_data_t session_id, const vssq_messenger_user_t *owner, vssq_error_t *error);

//
//  Return string representation of the given number.
//
VSSQ_PUBLIC vsc_str_buffer_t *
vssq_messenger_group_epoch_keyknox_storage_stringify_epoch_num(size_t num);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE_H_INCLUDED
//  @end
