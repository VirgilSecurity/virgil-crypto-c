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
//  This module contains 'sha512' implementation.
// --------------------------------------------------------------------------

#ifndef VSF_SHA512_H_INCLUDED
#define VSF_SHA512_H_INCLUDED

#include "vsf_library.h"
#include "vsf_impl.h"
#include "vsf_hash_info.h"
#include "vsf_hash.h"
#include "vsf_hash_stream.h"
#include "vsf_hmac.h"
#include "vsf_hmac_stream.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Public integral constants.
//
enum {
    vsf_sha512_DIGEST_SIZE = 64
};

//
//  Handles implementation details.
//
typedef struct vsf_sha512_impl_t vsf_sha512_impl_t;

//
//  Return size of 'vsf_sha512_impl_t' type.
//
VSF_PUBLIC size_t
vsf_sha512_impl_size (void);

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_sha512_impl (vsf_sha512_impl_t* sha512_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC void
vsf_sha512_init (vsf_sha512_impl_t* sha512_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_sha512_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_sha512_cleanup (vsf_sha512_impl_t* sha512_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_sha512_impl_t*
vsf_sha512_new (void);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_sha512_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_sha512_destroy (vsf_sha512_impl_t** sha512_impl_ref);

//
//  Returns instance of the implemented interface 'hash info'.
//
VSF_PUBLIC const vsf_hash_info_api_t*
vsf_sha512_hash_info_api (void);

//
//  Returns instance of the implemented interface 'hash'.
//
VSF_PUBLIC const vsf_hash_api_t*
vsf_sha512_hash_api (void);

//
//  Returns instance of the implemented interface 'hmac'.
//
VSF_PUBLIC const vsf_hmac_api_t*
vsf_sha512_hmac_api (void);

//
//  Calculate hash over given data.
//
VSF_PUBLIC void
vsf_sha512_hash (const byte* data, size_t data_len, byte* digest, size_t digest_len);

//
//  Start a new hashing.
//
VSF_PUBLIC void
vsf_sha512_start (vsf_sha512_impl_t* sha512_impl);

//
//  Add given data to the hash.
//
VSF_PUBLIC void
vsf_sha512_update (vsf_sha512_impl_t* sha512_impl, const byte* data, size_t data_len);

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSF_PUBLIC void
vsf_sha512_finish (vsf_sha512_impl_t* sha512_impl, byte* digest, size_t digest_len);

//
//  Calculate hmac over given data.
//
VSF_PUBLIC void
vsf_sha512_hmac (const byte* key, size_t key_len, const byte* data, size_t data_len, byte* hmac,
        size_t hmac_len);

//
//  Reset HMAC.
//
VSF_PUBLIC void
vsf_sha512_hmac_reset (vsf_sha512_impl_t* sha512_impl);

//
//  Start a new HMAC.
//
VSF_PUBLIC void
vsf_sha512_hmac_start (vsf_sha512_impl_t* sha512_impl, const byte* key, size_t key_len);

//
//  Add given data to the HMAC.
//
VSF_PUBLIC void
vsf_sha512_hmac_update (vsf_sha512_impl_t* sha512_impl, const byte* data, size_t data_len);

//
//  Accompilsh HMAC and return it's result (a message digest).
//
VSF_PUBLIC void
vsf_sha512_hmac_finish (vsf_sha512_impl_t* sha512_impl, byte* hmac, size_t hmac_len);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_SHA512_H_INCLUDED
//  @end
