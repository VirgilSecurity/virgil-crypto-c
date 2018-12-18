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
//  This module contains 'kdf1' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_KDF1_H_INCLUDED
#define VSCF_KDF1_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handles implementation details.
//
typedef struct vscf_kdf1_impl_t vscf_kdf1_impl_t;

//
//  Return size of 'vscf_kdf1_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_kdf1_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_kdf1_impl(vscf_kdf1_impl_t *kdf1_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_kdf1_init(vscf_kdf1_impl_t *kdf1_impl);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_kdf1_init()'.
//
VSCF_PUBLIC void
vscf_kdf1_cleanup(vscf_kdf1_impl_t *kdf1_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_kdf1_impl_t *
vscf_kdf1_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf1_new()'.
//
VSCF_PUBLIC void
vscf_kdf1_delete(vscf_kdf1_impl_t *kdf1_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf1_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_kdf1_destroy(vscf_kdf1_impl_t **kdf1_impl_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_kdf1_impl_t *
vscf_kdf1_shallow_copy(vscf_kdf1_impl_t *kdf1_impl);

//
//  Setup dependency to the interface 'hash stream' with shared ownership.
//
VSCF_PUBLIC void
vscf_kdf1_use_hash(vscf_kdf1_impl_t *kdf1_impl, vscf_impl_t *hash);

//
//  Setup dependency to the interface 'hash stream' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_kdf1_take_hash(vscf_kdf1_impl_t *kdf1_impl, vscf_impl_t *hash);

//
//  Release dependency to the interface 'hash stream'.
//
VSCF_PUBLIC void
vscf_kdf1_release_hash(vscf_kdf1_impl_t *kdf1_impl);

//
//  Derive key of the requested length from the given data.
//
VSCF_PUBLIC void
vscf_kdf1_derive(vscf_kdf1_impl_t *kdf1_impl, vsc_data_t data, size_t key_len, vsc_buffer_t *key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KDF1_H_INCLUDED
//  @end
