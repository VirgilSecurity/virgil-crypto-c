//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Handles padding parameters and constraints.
// --------------------------------------------------------------------------

#ifndef VSCF_PADDING_PARAMS_H_INCLUDED
#define VSCF_PADDING_PARAMS_H_INCLUDED

#include "vscf_library.h"

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
    vscf_padding_params_DEFAULT_FRAME_MIN = 32,
    vscf_padding_params_DEFAULT_FRAME = 160,
    vscf_padding_params_DEFAULT_FRAME_MAX = 256
};

//
//  Handle 'padding params' context.
//
typedef struct vscf_padding_params_t vscf_padding_params_t;

//
//  Return size of 'vscf_padding_params_t'.
//
VSCF_PUBLIC size_t
vscf_padding_params_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_padding_params_init(vscf_padding_params_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_padding_params_cleanup(vscf_padding_params_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_new(void);

//
//  Perform initialization of pre-allocated context.
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
VSCF_PUBLIC void
vscf_padding_params_init_with_constraints(vscf_padding_params_t *self, size_t frame, size_t frame_max);

//
//  Allocate class context and perform it's initialization.
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_new_with_constraints(size_t frame, size_t frame_max);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_padding_params_delete(vscf_padding_params_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_padding_params_new ()'.
//
VSCF_PUBLIC void
vscf_padding_params_destroy(vscf_padding_params_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_shallow_copy(vscf_padding_params_t *self);

//
//  Return padding frame in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_params_frame(const vscf_padding_params_t *self);

//
//  Return maximum padding frame in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_params_frame_max(const vscf_padding_params_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PADDING_PARAMS_H_INCLUDED
//  @end
