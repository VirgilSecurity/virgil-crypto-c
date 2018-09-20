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
//  Types of the 'rsa private key' implementation.
//  This types SHOULD NOT be used directly.
//  The only purpose of including this module is to place implementation
//  object in the stack memory.
// --------------------------------------------------------------------------

#ifndef VSCF_RSA_PRIVATE_KEY_IMPL_H_INCLUDED
#define VSCF_RSA_PRIVATE_KEY_IMPL_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl_private.h"
#include "vscf_rsa_private_key.h"
#include "vscf_hash.h"
#include "vscf_impl.h"

#include <mbedtls/rsa.h>
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
struct vscf_rsa_private_key_impl_t {
    //
    //  Compile-time known information about this implementation.
    //
    const vscf_impl_info_t *info;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface api 'hash'.
    //
    const vscf_hash_api_t *hash;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *random;
    //
    //  Dependency to the interface 'asn1 reader'.
    //
    vscf_impl_t *asn1rd;
    //
    //  Dependency to the interface 'asn1 writer'.
    //
    vscf_impl_t *asn1wr;
    //
    //  Implementation specific context.
    //
    mbedtls_rsa_context rsa_ctx;
    //
    //  Implementation specific context.
    //
    size_t gen_bitlen;
    //
    //  Implementation specific context.
    //
    size_t gen_exponent;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RSA_PRIVATE_KEY_IMPL_H_INCLUDED
//  @end
