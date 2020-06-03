//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  Class responsible for verifying "raw card".
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_raw_card_verifier.h"
#include "vssc_memory.h"
#include "vssc_assert.h"

#include <virgil/crypto/foundation/vscf_verifier.h>
#include <virgil/crypto/foundation/private/vscf_verifier_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Identifier of virgil signature.
//
static const char k_virgil_signer_id[] = "virgil";

//
//  Identifier of virgil signature.
//
static const vsc_str_t k_virgil_signer_id_str = {
    k_virgil_signer_id,
    sizeof(k_virgil_signer_id) - 1
};

//
//  Identifier of self-signature.
//
static const char k_self_signer_id[] = "self";

//
//  Identifier of self-signature.
//
static const vsc_str_t k_self_signer_id_str = {
    k_self_signer_id,
    sizeof(k_self_signer_id) - 1
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Verifies given "raw card" with provided signer and public key.
//
VSSC_PUBLIC bool
vssc_raw_card_verifier_verify(const vssc_raw_card_t *raw_card, vsc_str_t signer_id, const vscf_impl_t *public_key) {

    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT_PTR(public_key);

    bool verified = false;
    vscf_verifier_t *verifier = vscf_verifier_new();

    for (const vssc_raw_card_signature_list_t *signature_it = vssc_raw_card_signatures(raw_card);
            (signature_it != NULL) && vssc_raw_card_signature_list_has_item(signature_it);
            signature_it = vssc_raw_card_signature_list_next(signature_it)) {

        const vssc_raw_card_signature_t *signature = vssc_raw_card_signature_list_item(signature_it);
        vsc_str_t signature_signer_id = vssc_raw_card_signature_signer_id(signature);

        if (vsc_str_equal(signer_id, signature_signer_id)) {
            vsc_data_t content_snapshot = vssc_raw_card_content_snapshot(raw_card);
            vsc_data_t signature_snapshot = vssc_raw_card_content_snapshot(raw_card);

            vscf_verifier_append_data(verifier, content_snapshot);
            vscf_verifier_append_data(verifier, signature_snapshot);

            verified = vscf_verifier_verify(verifier, public_key);

            break;
        }
    }

    vscf_verifier_destroy(&verifier);

    return verified;
}

//
//  Verifies self-signature.
//
VSSC_PUBLIC bool
vssc_raw_card_verifier_verify_self(const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key) {

    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT_PTR(public_key);

    return vssc_raw_card_verifier_verify(raw_card, k_self_signer_id_str, public_key);
}

//
//  Verifies signature of Virgil Cards Service.
//
VSSC_PUBLIC bool
vssc_raw_card_verifier_verify_virgil(const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key) {

    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT_PTR(public_key);

    return vssc_raw_card_verifier_verify(raw_card, k_virgil_signer_id_str, public_key);
}
