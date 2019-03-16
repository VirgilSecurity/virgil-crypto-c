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
//  Create algorithms based on the given information.
// --------------------------------------------------------------------------

#ifndef VSCF_ALG_FACTORY_H_INCLUDED
#define VSCF_ALG_FACTORY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_raw_key.h"
#include "vscf_impl.h"

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
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_hash_from_info(const vscf_impl_t *alg_info);

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_mac_from_info(const vscf_impl_t *alg_info);

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_kdf_from_info(const vscf_impl_t *alg_info);

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_info(const vscf_impl_t *alg_info);

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_from_info(const vscf_impl_t *alg_info);

//
//  Create algorithm that implements "public key" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_public_key_from_raw_key(const vscf_raw_key_t *raw_key);

//
//  Create algorithm that implements "private key" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_private_key_from_raw_key(const vscf_raw_key_t *raw_key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ALG_FACTORY_H_INCLUDED
//  @end
