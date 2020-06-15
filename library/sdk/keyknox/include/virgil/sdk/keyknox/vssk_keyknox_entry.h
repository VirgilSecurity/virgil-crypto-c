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
//  A new or stored record within the Virgil Keyknox Service.
// --------------------------------------------------------------------------

#ifndef VSSK_KEYKNOX_ENTRY_H_INCLUDED
#define VSSK_KEYKNOX_ENTRY_H_INCLUDED

#include "vssk_library.h"

#if !VSSK_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if !VSSK_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_string_list.h>
#endif

#if VSSK_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSSK_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSC/vssc_string_list.h>
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
//  Handle 'keyknox entry' context.
//
#ifndef VSSK_KEYKNOX_ENTRY_T_DEFINED
#define VSSK_KEYKNOX_ENTRY_T_DEFINED
    typedef struct vssk_keyknox_entry_t vssk_keyknox_entry_t;
#endif // VSSK_KEYKNOX_ENTRY_T_DEFINED

//
//  Return size of 'vssk_keyknox_entry_t'.
//
VSSK_PUBLIC size_t
vssk_keyknox_entry_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init(vssk_keyknox_entry_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSK_PUBLIC void
vssk_keyknox_entry_cleanup(vssk_keyknox_entry_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init_with(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with(vsc_str_t root, vsc_str_t path, vsc_str_t key, const vssc_string_list_t *identities,
        vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PRIVATE void
vssk_keyknox_entry_init_with_disown(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref);

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PRIVATE vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_disown(vsc_str_t root, vsc_str_t path, vsc_str_t key, vssc_string_list_t **identities_ref,
        vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref, vsc_buffer_t **hash_ref);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined Keyknox entry.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init_with_owner(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined Keyknox entry.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_owner(vsc_str_t owner, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined Keyknox entry.
//
VSSK_PRIVATE void
vssk_keyknox_entry_init_with_owner_disown(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined Keyknox entry.
//
VSSK_PRIVATE vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_owner_disown(vsc_str_t owner, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSK_PUBLIC void
vssk_keyknox_entry_delete(const vssk_keyknox_entry_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssk_keyknox_entry_new ()'.
//
VSSK_PUBLIC void
vssk_keyknox_entry_destroy(vssk_keyknox_entry_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_shallow_copy(vssk_keyknox_entry_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSK_PUBLIC const vssk_keyknox_entry_t *
vssk_keyknox_entry_shallow_copy_const(const vssk_keyknox_entry_t *self);

//
//  Return owner.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_owner(const vssk_keyknox_entry_t *self);

//
//  Return root path.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_root(const vssk_keyknox_entry_t *self);

//
//  Return second path.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_path(const vssk_keyknox_entry_t *self);

//
//  Return key.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_key(const vssk_keyknox_entry_t *self);

//
//  Return list of users that have access to the entry.
//
VSSK_PUBLIC const vssc_string_list_t *
vssk_keyknox_entry_identities(const vssk_keyknox_entry_t *self);

//
//  Return meta.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_meta(const vssk_keyknox_entry_t *self);

//
//  Return value.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_value(const vssk_keyknox_entry_t *self);

//
//  Return hash.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_hash(const vssk_keyknox_entry_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSK_KEYKNOX_ENTRY_H_INCLUDED
//  @end
