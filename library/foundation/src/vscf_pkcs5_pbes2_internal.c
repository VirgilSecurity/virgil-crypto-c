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

#include "vscf_pkcs5_pbes2_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_pkcs5_pbes2_defs.h"
#include "vscf_encrypt.h"
#include "vscf_encrypt_api.h"
#include "vscf_decrypt.h"
#include "vscf_decrypt_api.h"
#include "vscf_cipher.h"
#include "vscf_pkcs5_pbkdf2.h"
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
vscf_pkcs5_pbes2_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'encrypt api'.
//
static const vscf_encrypt_api_t encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'encrypt' MUST be equal to the 'vscf_api_tag_ENCRYPT'.
    //
    vscf_api_tag_ENCRYPT,
    //
    //  Encrypt given data.
    //
    (vscf_encrypt_api_encrypt_fn)vscf_pkcs5_pbes2_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_encrypt_api_encrypted_len_fn)vscf_pkcs5_pbes2_encrypted_len
};

//
//  Configuration of the interface API 'decrypt api'.
//
static const vscf_decrypt_api_t decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'decrypt' MUST be equal to the 'vscf_api_tag_DECRYPT'.
    //
    vscf_api_tag_DECRYPT,
    //
    //  Decrypt given data.
    //
    (vscf_decrypt_api_decrypt_fn)vscf_pkcs5_pbes2_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_decrypt_api_decrypted_len_fn)vscf_pkcs5_pbes2_decrypted_len
};

//
//  Compile-time known information about 'pkcs5 pbes2' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_pkcs5_pbes2_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_pkcs5_pbes2_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_pkcs5_pbes2_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_init(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vscf_zeroize(pkcs5_pbes2, sizeof(vscf_pkcs5_pbes2_t));

    pkcs5_pbes2->info = &info;
    pkcs5_pbes2->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbes2_init()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_cleanup(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    if (pkcs5_pbes2 == NULL || pkcs5_pbes2->info == NULL) {
        return;
    }

    if (pkcs5_pbes2->refcnt == 0) {
        return;
    }

    if (--pkcs5_pbes2->refcnt > 0) {
        return;
    }

    vscf_pkcs5_pbes2_release_pbkdf2(pkcs5_pbes2);
    vscf_pkcs5_pbes2_release_cipher(pkcs5_pbes2);

    vscf_zeroize(pkcs5_pbes2, sizeof(vscf_pkcs5_pbes2_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pkcs5_pbes2_t *
vscf_pkcs5_pbes2_new(void) {

    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = (vscf_pkcs5_pbes2_t *) vscf_alloc(sizeof (vscf_pkcs5_pbes2_t));
    VSCF_ASSERT_ALLOC(pkcs5_pbes2);

    vscf_pkcs5_pbes2_init(pkcs5_pbes2);

    return pkcs5_pbes2;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbes2_new()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_delete(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    vscf_pkcs5_pbes2_cleanup(pkcs5_pbes2);

    if (pkcs5_pbes2 && (pkcs5_pbes2->refcnt == 0)) {
        vscf_dealloc(pkcs5_pbes2);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbes2_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_destroy(vscf_pkcs5_pbes2_t **pkcs5_pbes2_ref) {

    VSCF_ASSERT_PTR(pkcs5_pbes2_ref);

    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = *pkcs5_pbes2_ref;
    *pkcs5_pbes2_ref = NULL;

    vscf_pkcs5_pbes2_delete(pkcs5_pbes2);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_pkcs5_pbes2_t *
vscf_pkcs5_pbes2_shallow_copy(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    // Proxy to the parent implementation.
    return (vscf_pkcs5_pbes2_t *)vscf_impl_shallow_copy((vscf_impl_t *)pkcs5_pbes2);
}

//
//  Return size of 'vscf_pkcs5_pbes2_t' type.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_impl_size(void) {

    return sizeof (vscf_pkcs5_pbes2_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs5_pbes2_impl(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    return (vscf_impl_t *)(pkcs5_pbes2);
}

//
//  Setup dependency to the implementation 'pkcs5 pbkdf2' with shared ownership.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_use_pbkdf2(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vscf_pkcs5_pbkdf2_t *pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pbkdf2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->pbkdf2 == NULL);

    pkcs5_pbes2->pbkdf2 = vscf_pkcs5_pbkdf2_shallow_copy(pbkdf2);
}

//
//  Setup dependency to the implementation 'pkcs5 pbkdf2' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_take_pbkdf2(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vscf_pkcs5_pbkdf2_t *pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pbkdf2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->pbkdf2 == NULL);

    pkcs5_pbes2->pbkdf2 = pbkdf2;
}

//
//  Release dependency to the implementation 'pkcs5 pbkdf2'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_release_pbkdf2(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vscf_pkcs5_pbkdf2_destroy(&pkcs5_pbes2->pbkdf2);
}

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_use_cipher(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    pkcs5_pbes2->cipher = vscf_impl_shallow_copy(cipher);
}

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_take_cipher(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    pkcs5_pbes2->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_release_cipher(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vscf_impl_destroy(&pkcs5_pbes2->cipher);
}

static const vscf_api_t *
vscf_pkcs5_pbes2_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_DECRYPT:
            return (const vscf_api_t *) &decrypt_api;
        case vscf_api_tag_ENCRYPT:
            return (const vscf_api_t *) &encrypt_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
