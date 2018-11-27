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

#ifndef VSCE_SIMPLE_SWU_H_INCLUDED
#define VSCE_SIMPLE_SWU_H_INCLUDED

#include <mbedtls/ecp.h>
#include "vsce_library.h"
#include "vsce_error.h"

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
    vsce_simple_swu_HASH_LEN = 32
};

//
//  Handle 'simple swu' context.
//
typedef struct vsce_simple_swu_t vsce_simple_swu_t;

//
//  Return size of 'vsce_simple_swu_t'.
//
VSCE_PUBLIC size_t
vsce_simple_swu_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_simple_swu_init(vsce_simple_swu_t *simple_swu_ctx);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_simple_swu_cleanup(vsce_simple_swu_t *simple_swu_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_simple_swu_t *
vsce_simple_swu_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_simple_swu_delete(vsce_simple_swu_t *simple_swu_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_simple_swu_new ()'.
//
VSCE_PUBLIC void
vsce_simple_swu_destroy(vsce_simple_swu_t **simple_swu_ctx_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_simple_swu_t *
vsce_simple_swu_copy(vsce_simple_swu_t *simple_swu_ctx);

VSCE_PUBLIC vsce_error_t
vsce_simple_swu_bignum_to_point(vsce_simple_swu_t *simple_swu_ctx, const mbedtls_mpi *t, mbedtls_ecp_point *p);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_SIMPLE_SWU_H_INCLUDED
//  @end
