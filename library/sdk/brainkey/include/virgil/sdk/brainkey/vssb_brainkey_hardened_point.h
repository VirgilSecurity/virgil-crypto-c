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
//  Handles Brainkey hardened point returned by the service.
// --------------------------------------------------------------------------

#ifndef VSSB_BRAINKEY_HARDENED_POINT_H_INCLUDED
#define VSSB_BRAINKEY_HARDENED_POINT_H_INCLUDED

#include "vssb_library.h"

#if !VSSB_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSSB_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'brainkey hardened point' context.
//
#ifndef VSSB_BRAINKEY_HARDENED_POINT_T_DEFINED
#define VSSB_BRAINKEY_HARDENED_POINT_T_DEFINED
    typedef struct vssb_brainkey_hardened_point_t vssb_brainkey_hardened_point_t;
#endif // VSSB_BRAINKEY_HARDENED_POINT_T_DEFINED

//
//  Return size of 'vssb_brainkey_hardened_point_t'.
//
VSSB_PUBLIC size_t
vssb_brainkey_hardened_point_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_init(vssb_brainkey_hardened_point_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_cleanup(vssb_brainkey_hardened_point_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_delete(const vssb_brainkey_hardened_point_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssb_brainkey_hardened_point_new ()'.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_destroy(vssb_brainkey_hardened_point_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_shallow_copy(vssb_brainkey_hardened_point_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSB_PUBLIC const vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_shallow_copy_const(const vssb_brainkey_hardened_point_t *self);

//
//  Return Brainkey hardened point.
//
VSSB_PUBLIC vsc_data_t
vssb_brainkey_hardened_point_value(const vssb_brainkey_hardened_point_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSB_BRAINKEY_HARDENED_POINT_H_INCLUDED
//  @end
