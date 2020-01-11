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

#ifndef VSCF_SIMPLE_SWU_H_INCLUDED
#define VSCF_SIMPLE_SWU_H_INCLUDED

#include "vscf_library.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

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
//  Public integral constants.
//
enum {
    vscf_simple_swu_HASH_LEN = 32
};

//
//  Handle 'simple swu' context.
//
typedef struct vscf_simple_swu_t vscf_simple_swu_t;

//
//  Return size of 'vscf_simple_swu_t'.
//
VSCF_PUBLIC size_t
vscf_simple_swu_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_simple_swu_init(vscf_simple_swu_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_simple_swu_cleanup(vscf_simple_swu_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_simple_swu_t *
vscf_simple_swu_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_simple_swu_delete(vscf_simple_swu_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_simple_swu_new ()'.
//
VSCF_PUBLIC void
vscf_simple_swu_destroy(vscf_simple_swu_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_simple_swu_t *
vscf_simple_swu_shallow_copy(vscf_simple_swu_t *self);

VSCF_PUBLIC void
vscf_simple_swu_bignum_to_point(vscf_simple_swu_t *self, const mbedtls_mpi *t, mbedtls_ecp_point *p);

VSCF_PUBLIC void
vscf_simple_swu_data_to_point(vscf_simple_swu_t *self, vsc_data_t data, mbedtls_ecp_point *p);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SIMPLE_SWU_H_INCLUDED
//  @end
