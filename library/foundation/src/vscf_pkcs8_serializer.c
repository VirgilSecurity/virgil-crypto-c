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
//  This module contains 'pkcs8 serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs8_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_base64.h"
#include "vscf_asn1wr.h"
#include "vscf_pem.h"
#include "vscf_pem_title.h"
#include "vscf_pkcs8_der_serializer.h"
#include "vscf_asn1_writer.h"
#include "vscf_key_serializer.h"
#include "vscf_pkcs8_serializer_impl.h"
#include "vscf_pkcs8_serializer_internal.h"

#include <mbedtls/pem.h>

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
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_serializer_setup_defaults(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);

    if (NULL == pkcs8_serializer_impl->asn1_writer) {
        pkcs8_serializer_impl->asn1_writer = vscf_asn1wr_impl(vscf_asn1wr_new());
    }

    if (NULL == pkcs8_serializer_impl->der_serializer) {
        vscf_pkcs8_der_serializer_impl_t *der_serializer = vscf_pkcs8_der_serializer_new();
        vscf_pkcs8_der_serializer_use_asn1_writer(der_serializer, pkcs8_serializer_impl->asn1_writer);
        pkcs8_serializer_impl->der_serializer = vscf_pkcs8_der_serializer_impl(der_serializer);
    }

    return vscf_SUCCESS;
}

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_pkcs8_serializer_serialized_public_key_len(
        vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);
    VSCF_ASSERT_PTR(pkcs8_serializer_impl->der_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    size_t der_len = vscf_key_serializer_serialized_public_key_len(pkcs8_serializer_impl->der_serializer, public_key);
    size_t pem_len = vscf_pem_wrapped_len(vscf_pem_title_public_key, der_len);

    return pem_len;
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_serializer_serialize_public_key(
        vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);
    VSCF_ASSERT_PTR(pkcs8_serializer_impl->der_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(
            vsc_buffer_left(out) >= vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_impl, public_key));


    //  TODO: Optimize alloc.
    size_t der_len = vscf_key_serializer_serialized_public_key_len(pkcs8_serializer_impl->der_serializer, public_key);
    vsc_buffer_t *der = vsc_buffer_new_with_capacity(der_len);

    vscf_error_t status =
            vscf_key_serializer_serialize_public_key(pkcs8_serializer_impl->der_serializer, public_key, der);

    if (status != vscf_SUCCESS) {
        vsc_buffer_destroy(&der);
        return status;
    }

    vscf_pem_wrap(vscf_pem_title_public_key, vsc_buffer_data(der), out);

    vsc_buffer_destroy(&der);

    return vscf_SUCCESS;
}

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_pkcs8_serializer_serialized_private_key_len(
        vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);
    VSCF_ASSERT_PTR(pkcs8_serializer_impl->der_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    size_t der_len = vscf_key_serializer_serialized_private_key_len(pkcs8_serializer_impl->der_serializer, private_key);
    size_t pem_len = vscf_pem_wrapped_len(vscf_pem_title_private_key, der_len);

    return pem_len;
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_serializer_serialize_private_key(
        vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);
    VSCF_ASSERT_PTR(pkcs8_serializer_impl->der_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_left(out) >=
                vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer_impl, private_key));

    //  TODO: Optimize alloc.
    size_t der_len = vscf_key_serializer_serialized_private_key_len(pkcs8_serializer_impl->der_serializer, private_key);
    vsc_buffer_t *der = vsc_buffer_new_with_capacity(der_len);

    vscf_error_t status =
            vscf_key_serializer_serialize_private_key(pkcs8_serializer_impl->der_serializer, private_key, der);

    if (status != vscf_SUCCESS) {
        vsc_buffer_destroy(&der);
        return status;
    }

    vscf_pem_wrap(vscf_pem_title_private_key, vsc_buffer_data(der), out);

    vsc_buffer_destroy(&der);

    return vscf_SUCCESS;
}
