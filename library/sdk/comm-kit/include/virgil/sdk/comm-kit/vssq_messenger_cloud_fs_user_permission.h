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
//  Handles information about CloudFS user's permission to file or folder.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_cloud_fs_permission.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
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
//  Handle 'messenger cloud fs user permission' context.
//
#ifndef VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_T_DEFINED
#define VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_T_DEFINED
    typedef struct vssq_messenger_cloud_fs_user_permission_t vssq_messenger_cloud_fs_user_permission_t;
#endif // VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_T_DEFINED

//
//  Return size of 'vssq_messenger_cloud_fs_user_permission_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_user_permission_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_user_permission_init(vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_user_permission_cleanup(vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_user_permission_t *
vssq_messenger_cloud_fs_user_permission_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create an object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_user_permission_init_with(vssq_messenger_cloud_fs_user_permission_t *self, vsc_str_t identity,
        vssq_messenger_cloud_fs_permission_t permission);

//
//  Allocate class context and perform it's initialization.
//  Create an object with required fields.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_user_permission_t *
vssq_messenger_cloud_fs_user_permission_new_with(vsc_str_t identity, vssq_messenger_cloud_fs_permission_t permission);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_user_permission_delete(const vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_user_permission_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_user_permission_destroy(vssq_messenger_cloud_fs_user_permission_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_user_permission_t *
vssq_messenger_cloud_fs_user_permission_shallow_copy(vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_user_permission_t *
vssq_messenger_cloud_fs_user_permission_shallow_copy_const(const vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Return user's identity.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_cloud_fs_user_permission_identity(const vssq_messenger_cloud_fs_user_permission_t *self);

//
//  Return user's permission.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_permission_t
vssq_messenger_cloud_fs_user_permission_permission(const vssq_messenger_cloud_fs_user_permission_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_USER_PERMISSION_H_INCLUDED
//  @end
