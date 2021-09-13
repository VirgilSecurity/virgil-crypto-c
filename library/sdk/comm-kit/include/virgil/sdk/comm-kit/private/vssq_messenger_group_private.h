//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#ifndef VSSQ_MESSENGER_GROUP_PRIVATE_H_INCLUDED
#define VSSQ_MESSENGER_GROUP_PRIVATE_H_INCLUDED

#include "vssq_messenger_group.h"
#include "vssq_messenger_user_list.h"
#include "vssq_status.h"
#include "vssq_messenger_user.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_json_array.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_json_array.h>
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
//  Create a new group and register it in the cloud (Keyknox).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_create(vssq_messenger_group_t *self, vsc_str_t group_id,
        const vssq_messenger_user_list_t *participants) VSSQ_NODISCARD;

//
//  Load an existing group from the cloud (Keyknox).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load(vssq_messenger_group_t *self, vsc_str_t group_id,
        const vssq_messenger_user_t *owner) VSSQ_NODISCARD;

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_from_json(vssq_messenger_group_t *self, const vssc_json_object_t *json_obj) VSSQ_NODISCARD;

//
//  Load an existing group from a cached JSON value for a group messaging.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_from_json_str(vssq_messenger_group_t *self, vsc_str_t json_str) VSSQ_NODISCARD;

//
//  Load requested epoch if needed and store it within cache.
//
//  Note, method is thread-safe.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_group_load_epoch_if_needed(const vssq_messenger_group_t *self, size_t epoch_num) VSSQ_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_GROUP_PRIVATE_H_INCLUDED
//  @end
