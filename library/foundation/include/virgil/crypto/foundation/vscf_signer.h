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
//  Sign data of any size.
// --------------------------------------------------------------------------

#ifndef VSCF_SIGNER_H_INCLUDED
#define VSCF_SIGNER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

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
//  Handle 'signer' context.
//
typedef struct vscf_signer_t vscf_signer_t;

//
//  Return size of 'vscf_signer_t'.
//
VSCF_PUBLIC size_t
vscf_signer_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_signer_init(vscf_signer_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_signer_cleanup(vscf_signer_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_signer_t *
vscf_signer_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_signer_delete(vscf_signer_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_signer_new ()'.
//
VSCF_PUBLIC void
vscf_signer_destroy(vscf_signer_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_signer_t *
vscf_signer_shallow_copy(vscf_signer_t *self);

//
//  Setup dependency to the interface 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_signer_use_hash(vscf_signer_t *self, vscf_impl_t *hash);

//
//  Setup dependency to the interface 'hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_signer_take_hash(vscf_signer_t *self, vscf_impl_t *hash);

//
//  Release dependency to the interface 'hash'.
//
VSCF_PUBLIC void
vscf_signer_release_hash(vscf_signer_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_signer_use_random(vscf_signer_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_signer_take_random(vscf_signer_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_signer_release_random(vscf_signer_t *self);

//
//  Start a processing a new signature.
//
VSCF_PUBLIC void
vscf_signer_reset(vscf_signer_t *self);

//
//  Add given data to the signed data.
//
VSCF_PUBLIC void
vscf_signer_append_data(vscf_signer_t *self, vsc_data_t data);

//
//  Return length of the signature.
//
VSCF_PUBLIC size_t
vscf_signer_signature_len(const vscf_signer_t *self, const vscf_impl_t *private_key);

//
//  Accomplish signing and return signature.
//
VSCF_PUBLIC vscf_status_t
vscf_signer_sign(const vscf_signer_t *self, const vscf_impl_t *private_key, vsc_buffer_t *signature) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SIGNER_H_INCLUDED
//  @end
