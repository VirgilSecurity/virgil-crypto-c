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
//  This module contains 'kdf2' implementation.
// --------------------------------------------------------------------------

#ifndef VSF_KDF2_H_INCLUDED
#define VSF_KDF2_H_INCLUDED

#include "vsf_library.h"
#include "vsf_error.h"
#include "vsf_impl.h"
#include "vsf_kdf.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handles implementation details.
//
typedef struct vsf_kdf2_impl_t vsf_kdf2_impl_t;

//
//  Return size of 'vsf_kdf2_impl_t' type.
//
VSF_PUBLIC size_t
vsf_kdf2_impl_size (void);

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_kdf2_impl (vsf_kdf2_impl_t* kdf2_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_kdf2_init (vsf_kdf2_impl_t* kdf2_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_kdf2_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_kdf2_cleanup (vsf_kdf2_impl_t* kdf2_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_kdf2_impl_t*
vsf_kdf2_new (void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_kdf2_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_kdf2_delete (vsf_kdf2_impl_t* kdf2_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_kdf2_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_kdf2_destroy (vsf_kdf2_impl_t** kdf2_impl_ref);

//
//  Setup dependency to the interface 'hash stream' and keep ownership.
//
VSF_PUBLIC void
vsf_kdf2_use_hash_stream (vsf_kdf2_impl_t* kdf2_impl, vsf_impl_t* hash);

//
//  Setup dependency to the interface 'hash stream' and transfer ownership.
//
VSF_PUBLIC void
vsf_kdf2_take_hash_stream (vsf_kdf2_impl_t* kdf2_impl, vsf_impl_t** hash_ref);

//
//  Calculate hash over given data.
//
VSF_PUBLIC void
vsf_kdf2_derive (vsf_kdf2_impl_t* kdf2_impl, const byte* data, size_t data_len, byte* key,
        size_t key_len);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_KDF2_H_INCLUDED
//  @end
