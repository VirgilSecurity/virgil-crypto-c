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
//  Provide conversion logic between OID and algorithm tags.
// --------------------------------------------------------------------------

#ifndef VSCF_OID_H_INCLUDED
#define VSCF_OID_H_INCLUDED

#include "vscf_library.h"
#include "vscf_alg_id.h"
#include "vscf_oid_id.h"

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
//  Handle 'oid' context.
//
typedef struct vscf_oid_t vscf_oid_t;

//
//  Return size of 'vscf_oid_t'.
//
VSCF_PUBLIC size_t
vscf_oid_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_oid_init(vscf_oid_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_oid_cleanup(vscf_oid_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_oid_t *
vscf_oid_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_oid_delete(vscf_oid_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_oid_new ()'.
//
VSCF_PUBLIC void
vscf_oid_destroy(vscf_oid_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_oid_t *
vscf_oid_shallow_copy(vscf_oid_t *self);

//
//  Return OID for given algorithm identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_oid_from_alg_id(vscf_oid_t *self, void alg_id);

//
//  Return algorithm identifier for given OID.
//
VSCF_PUBLIC void
vscf_oid_to_alg_id(vscf_oid_t *self, vsc_data_t oid);

//
//  Return OID for a given identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_oid_from_id(vscf_oid_t *self, void oid_id);

//
//  Return identifier for a given OID.
//
VSCF_PUBLIC void
vscf_oid_to_id(vscf_oid_t *self, vsc_data_t oid);

//
//  Map oid identifier to the algorithm identifier.
//
VSCF_PUBLIC void
vscf_oid_id_to_alg_id(vscf_oid_t *self, void oid_id);

//
//  Return true if given OIDs are equal.
//
VSCF_PUBLIC bool
vscf_oid_equal(vscf_oid_t *self, vsc_data_t lhs, vsc_data_t rhs);

//
//  Return string representation of the given OID.
//
VSCF_PUBLIC void
vscf_oid_to_string(vscf_oid_t *self, vsc_data_t oid, const char *str);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_OID_H_INCLUDED
//  @end
