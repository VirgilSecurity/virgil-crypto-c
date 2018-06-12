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
//  This module contains 'hkdf' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_HKDF_H_INCLUDED
#define VSCF_HKDF_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_ex_kdf.h"
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
typedef struct vscf_hkdf_impl_t vscf_hkdf_impl_t;

//
//  Return size of 'vscf_hkdf_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_hkdf_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t*
vscf_hkdf_impl(vscf_hkdf_impl_t* hkdf_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC vscf_error_t
vscf_hkdf_init(vscf_hkdf_impl_t* hkdf_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hkdf_cleanup(vscf_hkdf_impl_t* hkdf_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hkdf_impl_t*
vscf_hkdf_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hkdf_delete(vscf_hkdf_impl_t* hkdf_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hkdf_destroy(vscf_hkdf_impl_t** hkdf_impl_ref);

//
//  Setup dependency to the interface 'hmac stream' and keep ownership.
//
VSCF_PUBLIC void
vscf_hkdf_use_hmac_stream(vscf_hkdf_impl_t* hkdf_impl, vscf_impl_t* hmac);

//
//  Setup dependency to the interface 'hmac stream' and transfer ownership.
//
VSCF_PUBLIC void
vscf_hkdf_take_hmac_stream(vscf_hkdf_impl_t* hkdf_impl, vscf_impl_t** hmac_ref);

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_hkdf_derive(vscf_hkdf_impl_t* hkdf_impl, const byte* data, size_t data_len, const byte* salt, size_t salt_len,
        const byte* info, size_t info_len, byte* key, size_t key_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_HKDF_H_INCLUDED
//  @end
