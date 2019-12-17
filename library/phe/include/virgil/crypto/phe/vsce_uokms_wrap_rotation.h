//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#ifndef VSCE_UOKMS_WRAP_ROTATION_H_INCLUDED
#define VSCE_UOKMS_WRAP_ROTATION_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_status.h"

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'uokms wrap rotation' context.
//
typedef struct vsce_uokms_wrap_rotation_t vsce_uokms_wrap_rotation_t;

//
//  Return size of 'vsce_uokms_wrap_rotation_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_wrap_rotation_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_init(vsce_uokms_wrap_rotation_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_cleanup(vsce_uokms_wrap_rotation_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_wrap_rotation_t *
vsce_uokms_wrap_rotation_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_delete(vsce_uokms_wrap_rotation_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_wrap_rotation_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_destroy(vsce_uokms_wrap_rotation_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_wrap_rotation_t *
vsce_uokms_wrap_rotation_shallow_copy(vsce_uokms_wrap_rotation_t *self);

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_update_wrap(vsce_uokms_wrap_rotation_t *self, vsc_data_t wrap, vsc_data_t update_token,
        vsc_buffer_t *new_wrap) VSCE_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_UOKMS_WRAP_ROTATION_H_INCLUDED
//  @end
