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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'sha512' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_SHA512_H_INCLUDED
#define VSCF_SHA512_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"
#include "vscf_error.h"

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
//  Public integral constants.
//
enum {
    //
    //  Length of the digest (hashing output) in bytes.
    //
    vscf_sha512_DIGEST_LEN = 64,
    //
    //  Block length of the digest function in bytes.
    //
    vscf_sha512_BLOCK_LEN = 128
};

//
//  Handles implementation details.
//
typedef struct vscf_sha512_t vscf_sha512_t;

//
//  Return size of 'vscf_sha512_t' type.
//
VSCF_PUBLIC size_t
vscf_sha512_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha512_impl(vscf_sha512_t *sha512);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_sha512_init(vscf_sha512_t *sha512);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_sha512_init()'.
//
VSCF_PUBLIC void
vscf_sha512_cleanup(vscf_sha512_t *sha512);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sha512_t *
vscf_sha512_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new()'.
//
VSCF_PUBLIC void
vscf_sha512_delete(vscf_sha512_t *sha512);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha512_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sha512_destroy(vscf_sha512_t **sha512_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_sha512_t *
vscf_sha512_shallow_copy(vscf_sha512_t *sha512);

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_sha512_alg_id(const vscf_sha512_t *sha512);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha512_produce_alg_info(const vscf_sha512_t *sha512);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_sha512_restore_alg_info(vscf_sha512_t *sha512, const vscf_impl_t *alg_info);

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_sha512_hash(vsc_data_t data, vsc_buffer_t *digest);

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_sha512_start(vscf_sha512_t *sha512);

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_sha512_update(vscf_sha512_t *sha512, vsc_data_t data);

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_sha512_finish(vscf_sha512_t *sha512, vsc_buffer_t *digest);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SHA512_H_INCLUDED
//  @end
