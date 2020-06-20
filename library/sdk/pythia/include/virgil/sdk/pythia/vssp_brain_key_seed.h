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
//  Handles seed returned by the servie.
// --------------------------------------------------------------------------

#ifndef VSSP_BRAIN_KEY_SEED_H_INCLUDED
#define VSSP_BRAIN_KEY_SEED_H_INCLUDED

#include "vssp_library.h"

#if !VSSP_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSSP_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
//  Handle 'brain key seed' context.
//
#ifndef VSSP_BRAIN_KEY_SEED_T_DEFINED
#define VSSP_BRAIN_KEY_SEED_T_DEFINED
    typedef struct vssp_brain_key_seed_t vssp_brain_key_seed_t;
#endif // VSSP_BRAIN_KEY_SEED_T_DEFINED

//
//  Return size of 'vssp_brain_key_seed_t'.
//
VSSP_PUBLIC size_t
vssp_brain_key_seed_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSP_PUBLIC void
vssp_brain_key_seed_init(vssp_brain_key_seed_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSP_PUBLIC void
vssp_brain_key_seed_cleanup(vssp_brain_key_seed_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_brain_key_seed_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSP_PUBLIC void
vssp_brain_key_seed_delete(const vssp_brain_key_seed_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssp_brain_key_seed_new ()'.
//
VSSP_PUBLIC void
vssp_brain_key_seed_destroy(vssp_brain_key_seed_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_brain_key_seed_shallow_copy(vssp_brain_key_seed_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSP_PUBLIC const vssp_brain_key_seed_t *
vssp_brain_key_seed_shallow_copy_const(const vssp_brain_key_seed_t *self);

//
//  Return BrainKey seed.
//
VSSP_PUBLIC vsc_data_t
vssp_brain_key_seed_get(const vssp_brain_key_seed_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSP_BRAIN_KEY_SEED_H_INCLUDED
//  @end
