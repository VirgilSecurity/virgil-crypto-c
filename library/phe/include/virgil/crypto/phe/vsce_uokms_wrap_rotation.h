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
//  Implements wrap rotation.
// --------------------------------------------------------------------------

#ifndef VSCE_UOKMS_WRAP_ROTATION_H_INCLUDED
#define VSCE_UOKMS_WRAP_ROTATION_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_status.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'uokms wrap rotation' context.
//
#ifndef VSCE_UOKMS_WRAP_ROTATION_T_DEFINED
#define VSCE_UOKMS_WRAP_ROTATION_T_DEFINED
    typedef struct vsce_uokms_wrap_rotation_t vsce_uokms_wrap_rotation_t;
#endif // VSCE_UOKMS_WRAP_ROTATION_T_DEFINED

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
vsce_uokms_wrap_rotation_delete(const vsce_uokms_wrap_rotation_t *self);

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
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCE_PUBLIC const vsce_uokms_wrap_rotation_t *
vsce_uokms_wrap_rotation_shallow_copy_const(const vsce_uokms_wrap_rotation_t *self);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_use_operation_random(vsce_uokms_wrap_rotation_t *self, vscf_impl_t *operation_random);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transferred.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_take_operation_random(vsce_uokms_wrap_rotation_t *self, vscf_impl_t *operation_random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_release_operation_random(vsce_uokms_wrap_rotation_t *self);

//
//  Setups dependencies with default values.
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_setup_defaults(vsce_uokms_wrap_rotation_t *self) VSCE_NODISCARD;

//
//  Sets update token. Should be called only once and before any other function
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_set_update_token(vsce_uokms_wrap_rotation_t *self, vsc_data_t update_token) VSCE_NODISCARD;

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_update_wrap(vsce_uokms_wrap_rotation_t *self, vsc_data_t wrap,
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
