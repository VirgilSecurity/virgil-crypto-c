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
#include "vscf_base64.h"
#include "vscf_asn1rd.h"
#include "vscf_pem.h"
#include "vscf_pem_title.h"
#include "vscf_pkcs8_der_deserializer.h"
#include "vscf_asn1_reader.h"
#include "vscf_key_deserializer.h"
#include "vscf_pkcs8_deserializer_defs.h"
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
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs8_deserializer_setup_defaults(vscf_pkcs8_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_reader) {
        self->asn1_reader = vscf_asn1rd_impl(vscf_asn1rd_new());
    }

    if (NULL == self->der_deserializer) {
        vscf_pkcs8_der_deserializer_t *der_deserializer = vscf_pkcs8_der_deserializer_new();
        vscf_pkcs8_der_deserializer_use_asn1_reader(der_deserializer, self->asn1_reader);
        self->der_deserializer = vscf_pkcs8_der_deserializer_impl(der_deserializer);
    }

    return vscf_status_SUCCESS;
}

//
//  Deserialize given public key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_deserializer_deserialize_public_key(
        vscf_pkcs8_deserializer_t *self, vsc_data_t public_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(public_key_data));

    vsc_data_t title = vscf_pem_title(public_key_data);
    bool is_der = vsc_data_is_empty(title);

    if (is_der) {
        vscf_raw_key_t *raw_key =
                vscf_key_deserializer_deserialize_public_key(self->der_deserializer, public_key_data, error);

        return raw_key;
    }

    if (!vsc_data_equal(title, vsc_data_from_str(vscf_pem_title_public_key, vscf_pem_title_public_key_len))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY);
        return NULL;
    }

    //  TODO: Reduce allocation.
    size_t der_len = vscf_pem_unwrapped_len(public_key_data.len);
    vsc_buffer_t *der = vsc_buffer_new_with_capacity(der_len);
    vscf_status_t status = vscf_pem_unwrap(public_key_data, der);

    if (status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&der);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY);
        return NULL;
    }

    vscf_raw_key_t *raw_key =
            vscf_key_deserializer_deserialize_public_key(self->der_deserializer, vsc_buffer_data(der), error);

    vsc_buffer_destroy(&der);
    return raw_key;
}

//
//  Deserialize given private key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_deserializer_deserialize_private_key(
        vscf_pkcs8_deserializer_t *self, vsc_data_t private_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(private_key_data));

    vsc_data_t title = vscf_pem_title(private_key_data);
    bool is_der = vsc_data_is_empty(title);

    if (is_der) {
        vscf_raw_key_t *raw_key =
                vscf_key_deserializer_deserialize_private_key(self->der_deserializer, private_key_data, error);

        return raw_key;
    }

    if (!vsc_data_equal(title, vsc_data_from_str(vscf_pem_title_private_key, vscf_pem_title_private_key_len))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        return NULL;
    }

    //  TODO: Reduce allocation.
    size_t der_len = vscf_pem_unwrapped_len(private_key_data.len);
    vsc_buffer_t *der = vsc_buffer_new_with_capacity(der_len);
    vscf_status_t status = vscf_pem_unwrap(private_key_data, der);

    if (status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&der);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        return NULL;
    }

    vscf_raw_key_t *raw_key =
            vscf_key_deserializer_deserialize_private_key(self->der_deserializer, vsc_buffer_data(der), error);

    vsc_buffer_destroy(&der);
    return raw_key;
}
