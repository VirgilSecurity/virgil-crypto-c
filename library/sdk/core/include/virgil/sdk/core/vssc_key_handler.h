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


//  @description
// --------------------------------------------------------------------------
//  Handles public key or private key and it's identifier.
//
//  Note, that public key identifier equals to the private key identifier.
//  Note, a key identifier can be calculated with "key provider" class from the foundation library.
// --------------------------------------------------------------------------

#ifndef VSSC_KEY_HANDLER_H_INCLUDED
#define VSSC_KEY_HANDLER_H_INCLUDED

#include "vssc_library.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'key handler' context.
//
#ifndef VSSC_KEY_HANDLER_T_DEFINED
#define VSSC_KEY_HANDLER_T_DEFINED
    typedef struct vssc_key_handler_t vssc_key_handler_t;
#endif // VSSC_KEY_HANDLER_T_DEFINED

//
//  Return size of 'vssc_key_handler_t'.
//
VSSC_PUBLIC size_t
vssc_key_handler_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_key_handler_init(vssc_key_handler_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_key_handler_cleanup(vssc_key_handler_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_new(void);

//
//  Perform initialization of pre-allocated context.
//  Constructor.
//
VSSC_PUBLIC void
vssc_key_handler_init_with(vssc_key_handler_t *self, vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key);

//
//  Allocate class context and perform it's initialization.
//  Constructor.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_new_with(vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_key_handler_delete(const vssc_key_handler_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_key_handler_new ()'.
//
VSSC_PUBLIC void
vssc_key_handler_destroy(vssc_key_handler_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_shallow_copy(vssc_key_handler_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_key_handler_t *
vssc_key_handler_shallow_copy_const(const vssc_key_handler_t *self);

//
//  Return user's identity associated with the key.
//
VSSC_PUBLIC vsc_str_t
vssc_key_handler_identity(const vssc_key_handler_t *self);

//
//  Return public key identifier regardless of the underlying key - public or private.
//
VSSC_PUBLIC vsc_data_t
vssc_key_handler_key_id(const vssc_key_handler_t *self);

//
//  Return key.
//
VSSC_PUBLIC const vscf_impl_t *
vssc_key_handler_key(const vssc_key_handler_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_KEY_HANDLER_H_INCLUDED
//  @end
