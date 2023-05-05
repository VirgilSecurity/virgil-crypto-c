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
//  Verify data of any size.
//  Compatible with the class "signer".
// --------------------------------------------------------------------------

#ifndef VSCF_VERIFIER_H_INCLUDED
#define VSCF_VERIFIER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_status.h"
#include "vscf_impl.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'verifier' context.
//
typedef struct vscf_verifier_t vscf_verifier_t;

//
//  Return size of 'vscf_verifier_t'.
//
VSCF_PUBLIC size_t
vscf_verifier_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_verifier_init(vscf_verifier_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_verifier_cleanup(vscf_verifier_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_verifier_t *
vscf_verifier_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_verifier_delete(vscf_verifier_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_verifier_new ()'.
//
VSCF_PUBLIC void
vscf_verifier_destroy(vscf_verifier_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_verifier_t *
vscf_verifier_shallow_copy(vscf_verifier_t *self);

//
//  Start verifying a signature.
//
VSCF_PUBLIC vscf_status_t
vscf_verifier_reset(vscf_verifier_t *self, vsc_data_t signature) VSCF_NODISCARD;

//
//  Add given data to the signed data.
//
VSCF_PUBLIC void
vscf_verifier_append_data(vscf_verifier_t *self, vsc_data_t data);

//
//  Verify accumulated data.
//
VSCF_PUBLIC bool
vscf_verifier_verify(vscf_verifier_t *self, vscf_impl_t *public_key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_VERIFIER_H_INCLUDED
//  @end
