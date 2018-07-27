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
//  This module contains 'hmac224' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_HMAC224_H_INCLUDED
#define VSCF_HMAC224_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_hmac_info.h"
#include "vscf_hmac.h"
#include "vscf_hmac_stream.h"
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
    vscf_hmac224_DIGEST_SIZE = 28
};

//
//  Handles implementation details.
//
typedef struct vscf_hmac224_impl_t vscf_hmac224_impl_t;

//
//  Return size of 'vscf_hmac224_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_hmac224_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hmac224_impl(vscf_hmac224_impl_t *hmac224_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC vscf_error_t
vscf_hmac224_init(vscf_hmac224_impl_t *hmac224_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac224_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hmac224_cleanup(vscf_hmac224_impl_t *hmac224_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hmac224_impl_t *
vscf_hmac224_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac224_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hmac224_delete(vscf_hmac224_impl_t *hmac224_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac224_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hmac224_destroy(vscf_hmac224_impl_t **hmac224_impl_ref);

//
//  Returns instance of the implemented interface 'hmac info'.
//
VSCF_PUBLIC const vscf_hmac_info_api_t *
vscf_hmac224_hmac_info_api(void);

//
//  Returns instance of the implemented interface 'hmac'.
//
VSCF_PUBLIC const vscf_hmac_api_t *
vscf_hmac224_hmac_api(void);

//
//  Calculate hmac over given data.
//
VSCF_PUBLIC void
vscf_hmac224_hmac(const byte *key, size_t key_len, const byte *data, size_t data_len, byte *hmac, size_t hmac_len);

//
//  Reset HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_reset(vscf_hmac224_impl_t *hmac224_impl);

//
//  Start a new HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_start(vscf_hmac224_impl_t *hmac224_impl, const byte *key, size_t key_len);

//
//  Add given data to the HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_update(vscf_hmac224_impl_t *hmac224_impl, const byte *data, size_t data_len);

//
//  Accompilsh HMAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hmac224_finish(vscf_hmac224_impl_t *hmac224_impl, byte *hmac, size_t hmac_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_HMAC224_H_INCLUDED
//  @end
