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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ed25519_private_key_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ed25519_private_key_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_key.h"
#include "vscf_key_api.h"
#include "vscf_generate_key.h"
#include "vscf_generate_key_api.h"
#include "vscf_sign.h"
#include "vscf_sign_api.h"
#include "vscf_private_key.h"
#include "vscf_private_key_api.h"
#include "vscf_compute_shared_key.h"
#include "vscf_compute_shared_key_api.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_ed25519_private_key_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the 'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_ed25519_private_key_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_ed25519_private_key_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_ed25519_private_key_restore_alg_info
};

//
//  Configuration of the interface API 'key api'.
//
static const vscf_key_api_t key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key' MUST be equal to the 'vscf_api_tag_KEY'.
    //
    vscf_api_tag_KEY,
    //
    //  Link to the inherited interface API 'alg'.
    //
    &alg_api,
    //
    //  Length of the key in bytes.
    //
    (vscf_key_api_key_len_fn)vscf_ed25519_private_key_key_len,
    //
    //  Length of the key in bits.
    //
    (vscf_key_api_key_bitlen_fn)vscf_ed25519_private_key_key_bitlen
};

//
//  Configuration of the interface API 'generate key api'.
//
static const vscf_generate_key_api_t generate_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'generate_key' MUST be equal to the 'vscf_api_tag_GENERATE_KEY'.
    //
    vscf_api_tag_GENERATE_KEY,
    //
    //  Generate new private or secret key.
    //  Note, this operation can be slow.
    //
    (vscf_generate_key_api_generate_key_fn)vscf_ed25519_private_key_generate_key
};

//
//  Configuration of the interface API 'sign api'.
//
static const vscf_sign_api_t sign_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'sign' MUST be equal to the 'vscf_api_tag_SIGN'.
    //
    vscf_api_tag_SIGN,
    //
    //  Sign data given private key.
    //
    (vscf_sign_api_sign_fn)vscf_ed25519_private_key_sign,
    //
    //  Return length in bytes required to hold signature.
    //
    (vscf_sign_api_signature_len_fn)vscf_ed25519_private_key_signature_len
};

//
//  Configuration of the interface API 'private key api'.
//
static const vscf_private_key_api_t private_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'private_key' MUST be equal to the 'vscf_api_tag_PRIVATE_KEY'.
    //
    vscf_api_tag_PRIVATE_KEY,
    //
    //  Link to the inherited interface API 'key'.
    //
    &key_api,
    //
    //  Extract public part of the key.
    //
    (vscf_private_key_api_extract_public_key_fn)vscf_ed25519_private_key_extract_public_key,
    //
    //  Export private key in the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_private_key_api_export_private_key_fn)vscf_ed25519_private_key_export_private_key,
    //
    //  Return length in bytes required to hold exported private key.
    //
    (vscf_private_key_api_exported_private_key_len_fn)vscf_ed25519_private_key_exported_private_key_len,
    //
    //  Import private key from the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_private_key_api_import_private_key_fn)vscf_ed25519_private_key_import_private_key,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_ed25519_private_key_CAN_EXPORT_PRIVATE_KEY,
    //
    //  Define whether a private key can be imported or not.
    //
    vscf_ed25519_private_key_CAN_IMPORT_PRIVATE_KEY
};

//
//  Configuration of the interface API 'compute shared key api'.
//
static const vscf_compute_shared_key_api_t compute_shared_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'compute_shared_key' MUST be equal to the 'vscf_api_tag_COMPUTE_SHARED_KEY'.
    //
    vscf_api_tag_COMPUTE_SHARED_KEY,
    //
    //  Compute shared key for 2 asymmetric keys.
    //  Note, shared key can be used only for symmetric cryptography.
    //
    (vscf_compute_shared_key_api_compute_shared_key_fn)vscf_ed25519_private_key_compute_shared_key,
    //
    //  Return number of bytes required to hold shared key.
    //
    (vscf_compute_shared_key_api_shared_key_len_fn)vscf_ed25519_private_key_shared_key_len
};

//
//  Compile-time known information about 'ed25519 private key' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ed25519_private_key_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ed25519_private_key_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ed25519_private_key_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_init(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);

    vscf_zeroize(ed25519_private_key, sizeof(vscf_ed25519_private_key_t));

    ed25519_private_key->info = &info;
    ed25519_private_key->refcnt = 1;

    vscf_ed25519_private_key_init_ctx(ed25519_private_key);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ed25519_private_key_init()'.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_cleanup(vscf_ed25519_private_key_t *ed25519_private_key) {

    if (ed25519_private_key == NULL || ed25519_private_key->info == NULL) {
        return;
    }

    if (ed25519_private_key->refcnt == 0) {
        return;
    }

    if (--ed25519_private_key->refcnt > 0) {
        return;
    }

    vscf_ed25519_private_key_release_random(ed25519_private_key);

    vscf_ed25519_private_key_cleanup_ctx(ed25519_private_key);

    vscf_zeroize(ed25519_private_key, sizeof(vscf_ed25519_private_key_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ed25519_private_key_t *
vscf_ed25519_private_key_new(void) {

    vscf_ed25519_private_key_t *ed25519_private_key = (vscf_ed25519_private_key_t *) vscf_alloc(sizeof (vscf_ed25519_private_key_t));
    VSCF_ASSERT_ALLOC(ed25519_private_key);

    vscf_ed25519_private_key_init(ed25519_private_key);

    return ed25519_private_key;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_private_key_new()'.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_delete(vscf_ed25519_private_key_t *ed25519_private_key) {

    vscf_ed25519_private_key_cleanup(ed25519_private_key);

    if (ed25519_private_key && (ed25519_private_key->refcnt == 0)) {
        vscf_dealloc(ed25519_private_key);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_private_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_destroy(vscf_ed25519_private_key_t **ed25519_private_key_ref) {

    VSCF_ASSERT_PTR(ed25519_private_key_ref);

    vscf_ed25519_private_key_t *ed25519_private_key = *ed25519_private_key_ref;
    *ed25519_private_key_ref = NULL;

    vscf_ed25519_private_key_delete(ed25519_private_key);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_ed25519_private_key_t *
vscf_ed25519_private_key_shallow_copy(vscf_ed25519_private_key_t *ed25519_private_key) {

    // Proxy to the parent implementation.
    return (vscf_ed25519_private_key_t *)vscf_impl_shallow_copy((vscf_impl_t *)ed25519_private_key);
}

//
//  Return size of 'vscf_ed25519_private_key_t' type.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_impl_size(void) {

    return sizeof (vscf_ed25519_private_key_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_private_key_impl(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return (vscf_impl_t *)(ed25519_private_key);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_use_random(vscf_ed25519_private_key_t *ed25519_private_key, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT_PTR(ed25519_private_key->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    ed25519_private_key->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_take_random(vscf_ed25519_private_key_t *ed25519_private_key, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT_PTR(ed25519_private_key->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    ed25519_private_key->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_ed25519_private_key_release_random(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);

    vscf_impl_destroy(&ed25519_private_key->random);
}

static const vscf_api_t *
vscf_ed25519_private_key_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_COMPUTE_SHARED_KEY:
            return (const vscf_api_t *) &compute_shared_key_api;
        case vscf_api_tag_GENERATE_KEY:
            return (const vscf_api_t *) &generate_key_api;
        case vscf_api_tag_KEY:
            return (const vscf_api_t *) &key_api;
        case vscf_api_tag_PRIVATE_KEY:
            return (const vscf_api_t *) &private_key_api;
        case vscf_api_tag_SIGN:
            return (const vscf_api_t *) &sign_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
