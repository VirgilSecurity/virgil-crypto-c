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
//  This module contains 'hmac' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_HMAC_H_INCLUDED
#define VSCF_HMAC_H_INCLUDED

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
typedef struct vscf_hmac_t vscf_hmac_t;

//
//  Return size of 'vscf_hmac_t' type.
//
VSCF_PUBLIC size_t
vscf_hmac_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hmac_impl(vscf_hmac_t *hmac);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_hmac_init(vscf_hmac_t *hmac);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_hmac_init()'.
//
VSCF_PUBLIC void
vscf_hmac_cleanup(vscf_hmac_t *hmac);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hmac_t *
vscf_hmac_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac_new()'.
//
VSCF_PUBLIC void
vscf_hmac_delete(vscf_hmac_t *hmac);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hmac_destroy(vscf_hmac_t **hmac_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_hmac_t *
vscf_hmac_shallow_copy(vscf_hmac_t *hmac);

//
//  Setup dependency to the interface 'hash stream' with shared ownership.
//
VSCF_PUBLIC void
vscf_hmac_use_hash(vscf_hmac_t *hmac, vscf_impl_t *hash);

//
//  Setup dependency to the interface 'hash stream' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_hmac_take_hash(vscf_hmac_t *hmac, vscf_impl_t *hash);

//
//  Release dependency to the interface 'hash stream'.
//
VSCF_PUBLIC void
vscf_hmac_release_hash(vscf_hmac_t *hmac);

//
//  Size of the digest (mac output) in bytes.
//
VSCF_PUBLIC size_t
vscf_hmac_digest_len(vscf_hmac_t *hmac);

//
//  Calculate MAC over given data.
//
VSCF_PUBLIC void
vscf_hmac_mac(vscf_hmac_t *hmac, vsc_data_t key, vsc_data_t data, vsc_buffer_t *mac);

//
//  Start a new MAC.
//
VSCF_PUBLIC void
vscf_hmac_start(vscf_hmac_t *hmac, vsc_data_t key);

//
//  Add given data to the MAC.
//
VSCF_PUBLIC void
vscf_hmac_update(vscf_hmac_t *hmac, vsc_data_t data);

//
//  Accomplish MAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hmac_finish(vscf_hmac_t *hmac, vsc_buffer_t *mac);

//
//  Prepare to authenticate a new message with the same key
//  as the previous MAC operation.
//
VSCF_PUBLIC void
vscf_hmac_reset(vscf_hmac_t *hmac);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_HMAC_H_INCLUDED
//  @end
