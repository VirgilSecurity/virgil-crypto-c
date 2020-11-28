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
//  Handles a list of map's list of key-value pairs.
// --------------------------------------------------------------------------

#ifndef VSSC_STRING_MAP_BUCKET_H_INCLUDED
#define VSSC_STRING_MAP_BUCKET_H_INCLUDED

#include "vssc_library.h"
#include "vssc_error.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'string map bucket' context.
//
#ifndef VSSC_STRING_MAP_BUCKET_T_DEFINED
#define VSSC_STRING_MAP_BUCKET_T_DEFINED
    typedef struct vssc_string_map_bucket_t vssc_string_map_bucket_t;
#endif // VSSC_STRING_MAP_BUCKET_T_DEFINED

//
//  Return size of 'vssc_string_map_bucket_t'.
//
VSSC_PUBLIC size_t
vssc_string_map_bucket_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_string_map_bucket_init(vssc_string_map_bucket_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_string_map_bucket_cleanup(vssc_string_map_bucket_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_string_map_bucket_t *
vssc_string_map_bucket_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_string_map_bucket_delete(const vssc_string_map_bucket_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_string_map_bucket_new ()'.
//
VSSC_PUBLIC void
vssc_string_map_bucket_destroy(vssc_string_map_bucket_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_string_map_bucket_t *
vssc_string_map_bucket_shallow_copy(vssc_string_map_bucket_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_string_map_bucket_t *
vssc_string_map_bucket_shallow_copy_const(const vssc_string_map_bucket_t *self);

//
//  Add key-value pair to the bucket.
//
VSSC_PUBLIC void
vssc_string_map_bucket_put(vssc_string_map_bucket_t *self, vsc_str_t key, vsc_str_t value);

//
//  Remove all items.
//
VSSC_PUBLIC void
vssc_string_map_bucket_clear(vssc_string_map_bucket_t *self);

//
//  Find value for a given key.
//
VSSC_PUBLIC vsc_str_t
vssc_string_map_bucket_find(const vssc_string_map_bucket_t *self, vsc_str_t key, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_STRING_MAP_BUCKET_H_INCLUDED
//  @end
