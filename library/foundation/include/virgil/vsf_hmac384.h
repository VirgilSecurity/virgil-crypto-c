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
//  This module contains 'hmac384' implementation.
// --------------------------------------------------------------------------

#ifndef VSF_HMAC384_H_INCLUDED
#define VSF_HMAC384_H_INCLUDED

#include "vsf_library.h"
#include "vsf_error.h"
#include "vsf_impl.h"
#include "vsf_hmac_info.h"
#include "vsf_hmac.h"
#include "vsf_hmac_stream.h"
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
    vsf_hmac384_DIGEST_SIZE = 48
};

//
//  Handles implementation details.
//
typedef struct vsf_hmac384_impl_t vsf_hmac384_impl_t;

//
//  Return size of 'vsf_hmac384_impl_t' type.
//
VSF_PUBLIC size_t
vsf_hmac384_impl_size(void);

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_hmac384_impl(vsf_hmac384_impl_t* hmac384_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_hmac384_init(vsf_hmac384_impl_t* hmac384_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac384_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hmac384_cleanup(vsf_hmac384_impl_t* hmac384_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_hmac384_impl_t*
vsf_hmac384_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac384_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hmac384_delete(vsf_hmac384_impl_t* hmac384_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac384_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_hmac384_destroy(vsf_hmac384_impl_t** hmac384_impl_ref);

//
//  Returns instance of the implemented interface 'hmac info'.
//
VSF_PUBLIC const vsf_hmac_info_api_t*
vsf_hmac384_hmac_info_api(void);

//
//  Returns instance of the implemented interface 'hmac'.
//
VSF_PUBLIC const vsf_hmac_api_t*
vsf_hmac384_hmac_api(void);

//
//  Calculate hmac over given data.
//
VSF_PUBLIC void
vsf_hmac384_hmac(const byte* key, size_t key_len, const byte* data, size_t data_len, byte* hmac, size_t hmac_len);

//
//  Reset HMAC.
//
VSF_PUBLIC void
vsf_hmac384_reset(vsf_hmac384_impl_t* hmac384_impl);

//
//  Start a new HMAC.
//
VSF_PUBLIC void
vsf_hmac384_start(vsf_hmac384_impl_t* hmac384_impl, const byte* key, size_t key_len);

//
//  Add given data to the HMAC.
//
VSF_PUBLIC void
vsf_hmac384_update(vsf_hmac384_impl_t* hmac384_impl, const byte* data, size_t data_len);

//
//  Accompilsh HMAC and return it's result (a message digest).
//
VSF_PUBLIC void
vsf_hmac384_finish(vsf_hmac384_impl_t* hmac384_impl, byte* hmac, size_t hmac_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_HMAC384_H_INCLUDED
//  @end
