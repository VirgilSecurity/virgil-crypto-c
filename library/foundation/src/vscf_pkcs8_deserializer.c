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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'pkcs8 deserializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs8_deserializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_oid.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1_reader.h"
#include "vscf_pkcs8_deserializer_impl.h"
#include "vscf_pkcs8_deserializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_pkcs8_deserializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_pkcs8_deserializer_init_ctx(vscf_pkcs8_deserializer_impl_t *pkcs8_deserializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_deserializer_impl);

    pkcs8_deserializer_impl->der_deserializer = vscf_pkcs8_der_deserializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs8_deserializer_cleanup_ctx(vscf_pkcs8_deserializer_impl_t *pkcs8_deserializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_deserializer_impl);

    vscf_pkcs8_der_deserializer_destroy(&pkcs8_deserializer_impl->der_deserializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_deserializer_setup_defaults(vscf_pkcs8_deserializer_impl_t *pkcs8_deserializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_deserializer_impl);

    return vscf_SUCCESS;
}

//
//  Deserialize given public key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_deserializer_deserialize_public_key(
        vscf_pkcs8_deserializer_impl_t *pkcs8_deserializer_impl, vsc_data_t public_key_data, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(pkcs8_deserializer_impl);
    VSCF_ASSERT(vsc_data_is_valid(public_key_data));

    VSCF_UNUSED(error);
    //  TODO: This is STUB. Implement me.
    return NULL;
}

//
//  Deserialize given private key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_deserializer_deserialize_private_key(
        vscf_pkcs8_deserializer_impl_t *pkcs8_deserializer_impl, vsc_data_t private_key_data, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(pkcs8_deserializer_impl);
    VSCF_ASSERT(vsc_data_is_valid(private_key_data));

    VSCF_UNUSED(error);
    //  TODO: This is STUB. Implement me.
    return NULL;
}
