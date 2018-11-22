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
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1_writer.h"
#include "vscf_pkcs8_serializer_impl.h"
#include "vscf_pkcs8_serializer_internal.h"

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
//  Note, this method is called automatically when method vscf_pkcs8_serializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_init_ctx(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);

    pkcs8_serializer_impl->der_serializer = vscf_pkcs8_der_serializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_cleanup_ctx(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);

    vscf_pkcs8_der_serializer_destroy(&pkcs8_serializer_impl->der_serializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_serializer_setup_defaults(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);

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
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    //  TODO: This is STUB. Implement me.
    return 0;
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
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(
            vsc_buffer_left(out) >= vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_impl, public_key));
    //  TODO: This is STUB. Implement me.
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
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    //  TODO: This is STUB. Implement me.
    return 0;
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
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_left(out) >=
                vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_impl, private_key));
    //  TODO: This is STUB. Implement me.
    return vscf_SUCCESS;
}
