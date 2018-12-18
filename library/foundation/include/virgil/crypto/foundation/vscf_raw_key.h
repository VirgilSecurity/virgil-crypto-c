//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
//  Provide implementation agnostic representation of the asymmetric key.
// --------------------------------------------------------------------------

#ifndef VSCF_RAW_KEY_H_INCLUDED
#define VSCF_RAW_KEY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_key_alg.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
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
//  Handle 'raw key' context.
//
typedef struct vscf_raw_key_t vscf_raw_key_t;

//
//  Return size of 'vscf_raw_key_t'.
//
VSCF_PUBLIC size_t
vscf_raw_key_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_raw_key_init(vscf_raw_key_t *raw_key_ctx);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_raw_key_cleanup(vscf_raw_key_t *raw_key_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_new(void);

//
//  Creates raw key defined with algorithm and data.
//  Note, data is copied.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_new_with_data(vscf_key_alg_t alg, vsc_data_t raw_key_data);

//
//  Creates raw key defined with algorithm and buffer.
//
VSCF_PRIVATE vscf_raw_key_t *
vscf_raw_key_new_with_buffer(vscf_key_alg_t alg, vsc_buffer_t *buffer);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_raw_key_delete(vscf_raw_key_t *raw_key_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_raw_key_new ()'.
//
VSCF_PUBLIC void
vscf_raw_key_destroy(vscf_raw_key_t **raw_key_ctx_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_shallow_copy(vscf_raw_key_t *raw_key_ctx);

//
//  Returns asymmetric algorithm type that raw key belongs to.
//
VSCF_PUBLIC vscf_key_alg_t
vscf_raw_key_alg(vscf_raw_key_t *raw_key_ctx);

//
//  Return raw key data.
//
VSCF_PUBLIC vsc_data_t
vscf_raw_key_data(vscf_raw_key_t *raw_key_ctx);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RAW_KEY_H_INCLUDED
//  @end
