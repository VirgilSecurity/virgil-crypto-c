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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains 'sha384' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_SHA384_H_INCLUDED
#define VSCF_SHA384_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_hash_info.h"
#include "vscf_hash.h"
#include "vscf_hash_stream.h"

#include <virgil/common/vsc_data.h>
#include <virgil/common/vsc_buffer.h>
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
    vscf_sha384_DIGEST_LEN = 48
};

//
//  Handles implementation details.
//
typedef struct vscf_sha384_impl_t vscf_sha384_impl_t;

//
//  Return size of 'vscf_sha384_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_sha384_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha384_impl(vscf_sha384_impl_t *sha384_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_sha384_init(vscf_sha384_impl_t *sha384_impl);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_sha384_init()'.
//
VSCF_PUBLIC void
vscf_sha384_cleanup(vscf_sha384_impl_t *sha384_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sha384_impl_t *
vscf_sha384_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha384_new()'.
//
VSCF_PUBLIC void
vscf_sha384_delete(vscf_sha384_impl_t *sha384_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha384_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sha384_destroy(vscf_sha384_impl_t **sha384_impl_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_sha384_impl_t *
vscf_sha384_copy(vscf_sha384_impl_t *sha384_impl);

//
//  Returns instance of the implemented interface 'hash info'.
//
VSCF_PUBLIC const vscf_hash_info_api_t *
vscf_sha384_hash_info_api(void);

//
//  Returns instance of the implemented interface 'hash'.
//
VSCF_PUBLIC const vscf_hash_api_t *
vscf_sha384_hash_api(void);

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_sha384_hash(vsc_data_t data, vsc_buffer_t *digest);

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_sha384_start(vscf_sha384_impl_t *sha384_impl);

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_sha384_update(vscf_sha384_impl_t *sha384_impl, vsc_data_t data);

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_sha384_finish(vscf_sha384_impl_t *sha384_impl, vsc_buffer_t *digest);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SHA384_H_INCLUDED
//  @end
