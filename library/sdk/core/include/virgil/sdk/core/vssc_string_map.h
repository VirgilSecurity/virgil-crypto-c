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
//  Handles a map: key=string, value=string.
// --------------------------------------------------------------------------

#ifndef VSSC_STRING_MAP_H_INCLUDED
#define VSSC_STRING_MAP_H_INCLUDED

#include "vssc_library.h"
#include "vssc_error.h"
#include "vssc_string_list.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_str_buffer.h>
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
    vssc_string_map_CAPACITY_MAX = 1024 * 1024
};

//
//  Handle 'string map' context.
//
#ifndef VSSC_STRING_MAP_T_DEFINED
#define VSSC_STRING_MAP_T_DEFINED
    typedef struct vssc_string_map_t vssc_string_map_t;
#endif // VSSC_STRING_MAP_T_DEFINED

//
//  Return size of 'vssc_string_map_t'.
//
VSSC_PUBLIC size_t
vssc_string_map_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_string_map_init(vssc_string_map_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_string_map_cleanup(vssc_string_map_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create an optimal map.
//
VSSC_PUBLIC void
vssc_string_map_init_with_capacity(vssc_string_map_t *self, size_t capacity);

//
//  Allocate class context and perform it's initialization.
//  Create an optimal map.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_new_with_capacity(size_t capacity);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_string_map_delete(const vssc_string_map_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_string_map_new ()'.
//
VSSC_PUBLIC void
vssc_string_map_destroy(vssc_string_map_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_shallow_copy(vssc_string_map_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_string_map_t *
vssc_string_map_shallow_copy_const(const vssc_string_map_t *self);

//
//  Return map's capacity.
//
VSSC_PUBLIC size_t
vssc_string_map_capacity(const vssc_string_map_t *self);

//
//  Put a new pair to the map.
//
VSSC_PUBLIC void
vssc_string_map_put(vssc_string_map_t *self, vsc_str_t key, vsc_str_t value);

//
//  Return a value of the given key, or error.
//
VSSC_PUBLIC vsc_str_t
vssc_string_map_get(const vssc_string_map_t *self, vsc_str_t key, vssc_error_t *error);

//
//  Return a value of the given key, or error.
//
VSSC_PUBLIC const vsc_str_buffer_t *
vssc_string_map_get_inner(const vssc_string_map_t *self, vsc_str_t key, vssc_error_t *error);

//
//  Return true if value of the given key exists.
//
VSSC_PUBLIC bool
vssc_string_map_contains(const vssc_string_map_t *self, vsc_str_t key);

//
//  Return map keys.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_map_keys(const vssc_string_map_t *self);

//
//  Return map values.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_map_values(const vssc_string_map_t *self);

//
//  Return a new map with all keys and it values being swapped.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_swap_key_values(const vssc_string_map_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_STRING_MAP_H_INCLUDED
//  @end
