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

#ifndef VSCE_PHE_HASH_H_INCLUDED
#define VSCE_PHE_HASH_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"

#include <mbedtls/ecp.h>

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
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
//  Handle 'phe hash' context.
//
typedef struct vsce_phe_hash_t vsce_phe_hash_t;

//
//  Return size of 'vsce_phe_hash_t'.
//
VSCE_PUBLIC size_t
vsce_phe_hash_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_hash_init(vsce_phe_hash_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_hash_cleanup(vsce_phe_hash_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_phe_hash_delete(vsce_phe_hash_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_hash_new ()'.
//
VSCE_PUBLIC void
vsce_phe_hash_destroy(vsce_phe_hash_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_shallow_copy(vsce_phe_hash_t *self);

VSCE_PUBLIC void
vsce_phe_hash_derive_account_key(vsce_phe_hash_t *self, const mbedtls_ecp_point *m, vsc_buffer_t *account_key);

VSCE_PUBLIC void
vsce_phe_hash_hc0(vsce_phe_hash_t *self, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc0);

VSCE_PUBLIC void
vsce_phe_hash_hc1(vsce_phe_hash_t *self, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc1);

VSCE_PUBLIC void
vsce_phe_hash_hs0(vsce_phe_hash_t *self, vsc_data_t ns, mbedtls_ecp_point *hs0);

VSCE_PUBLIC void
vsce_phe_hash_hs1(vsce_phe_hash_t *self, vsc_data_t ns, mbedtls_ecp_point *hs1);

VSCE_PUBLIC void
vsce_phe_hash_hash_z_success(vsce_phe_hash_t *self, vsc_data_t server_public_key, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, mbedtls_mpi *z);

VSCE_PUBLIC void
vsce_phe_hash_hash_z_failure(vsce_phe_hash_t *self, vsc_data_t server_public_key, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, const mbedtls_ecp_point *term4, mbedtls_mpi *z);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_HASH_H_INCLUDED
//  @end
