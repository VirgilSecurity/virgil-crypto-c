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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'kdf alg info' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_KDF_ALG_INFO_H_INCLUDED
#define VSCF_KDF_ALG_INFO_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"
#include "vscf_simple_alg_info.h"

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
//  Handles implementation details.
//
typedef struct vscf_kdf_alg_info_t vscf_kdf_alg_info_t;

//
//  Return size of 'vscf_kdf_alg_info_t' type.
//
VSCF_PUBLIC size_t
vscf_kdf_alg_info_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_kdf_alg_info_impl(vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Set algorithm identificator
//
VSCF_PUBLIC vscf_kdf_alg_info_t *
vscf_kdf_alg_info_new_with_alg_id(vscf_alg_id_t alg_id);

//
//  Set algorithm identificator
//
VSCF_PUBLIC vscf_kdf_alg_info_t *
vscf_kdf_alg_info_new_with_members(vscf_alg_id_t alg_id, const vscf_simple_alg_info_t *hash_alg_info);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_kdf_alg_info_init(vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_kdf_alg_info_init()'.
//
VSCF_PUBLIC void
vscf_kdf_alg_info_cleanup(vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_kdf_alg_info_t *
vscf_kdf_alg_info_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf_alg_info_new()'.
//
VSCF_PUBLIC void
vscf_kdf_alg_info_delete(vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf_alg_info_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_kdf_alg_info_destroy(vscf_kdf_alg_info_t **kdf_alg_info_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_kdf_alg_info_t *
vscf_kdf_alg_info_shallow_copy(vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Provide algorithm identificator
//
VSCF_PUBLIC vscf_alg_id_t
vscf_kdf_alg_info_alg_id(vscf_kdf_alg_info_t *kdf_alg_info);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KDF_ALG_INFO_H_INCLUDED
//  @end
