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

#include "vscf_rsa_private_key_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_rsa_private_key_impl.h"
#include "vscf_key.h"
#include "vscf_key_api.h"
#include "vscf_generate_key.h"
#include "vscf_generate_key_api.h"
#include "vscf_private_key.h"
#include "vscf_private_key_api.h"
#include "vscf_decrypt.h"
#include "vscf_decrypt_api.h"
#include "vscf_sign.h"
#include "vscf_sign_api.h"
#include "vscf_export_private_key.h"
#include "vscf_export_private_key_api.h"
#include "vscf_import_private_key.h"
#include "vscf_import_private_key_api.h"
#include "vscf_hash.h"
#include "vscf_random.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_impl.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

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
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Length of the key in bytes.
    //
    (vscf_key_api_key_len_fn)vscf_rsa_private_key_key_len,
    //
    //  Length of the key in bits.
    //
    (vscf_key_api_key_bitlen_fn)vscf_rsa_private_key_key_bitlen
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
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Generate new private or secret key.
    //  Note, this operation can be slow.
    //
    (vscf_generate_key_api_generate_key_fn)vscf_rsa_private_key_generate_key
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
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Link to the inherited interface API 'key'.
    //
    &key_api,
    //
    //  Extract public part of the key.
    //
    (vscf_private_key_api_extract_public_key_fn)vscf_rsa_private_key_extract_public_key
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
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Decrypt given data.
    //
    (vscf_decrypt_api_decrypt_fn)vscf_rsa_private_key_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_decrypt_api_decrypted_len_fn)vscf_rsa_private_key_decrypted_len
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
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Sign data given private key.
    //
    (vscf_sign_api_sign_fn)vscf_rsa_private_key_sign,
    //
    //  Return length in bytes required to hold signature.
    //
    (vscf_sign_api_signature_len_fn)vscf_rsa_private_key_signature_len
};

//
//  Configuration of the interface API 'export private key api'.
//
static const vscf_export_private_key_api_t export_private_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'export_private_key' MUST be equal to the 'vscf_api_tag_EXPORT_PRIVATE_KEY'.
    //
    vscf_api_tag_EXPORT_PRIVATE_KEY,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Export private key in the binary format.
    //
    (vscf_export_private_key_api_export_private_key_fn)vscf_rsa_private_key_export_private_key,
    //
    //  Return length in bytes required to hold exported private key.
    //
    (vscf_export_private_key_api_exported_private_key_len_fn)vscf_rsa_private_key_exported_private_key_len
};

//
//  Configuration of the interface API 'import private key api'.
//
static const vscf_import_private_key_api_t import_private_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'import_private_key' MUST be equal to the 'vscf_api_tag_IMPORT_PRIVATE_KEY'.
    //
    vscf_api_tag_IMPORT_PRIVATE_KEY,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  Import private key from the binary format.
    //
    (vscf_import_private_key_api_import_private_key_fn)vscf_rsa_private_key_import_private_key
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vscf_api_t *api_array[] = {
    (const vscf_api_t *)&key_api,
    (const vscf_api_t *)&generate_key_api,
    (const vscf_api_t *)&private_key_api,
    (const vscf_api_t *)&decrypt_api,
    (const vscf_api_t *)&sign_api,
    (const vscf_api_t *)&export_private_key_api,
    (const vscf_api_t *)&import_private_key_api,
    NULL
};

//
//  Compile-time known information about 'rsa private key' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_RSA_PRIVATE_KEY,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_rsa_private_key_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_rsa_private_key_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_rsa_private_key_init(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    vscf_zeroize (rsa_private_key_impl, sizeof(vscf_rsa_private_key_impl_t));

    rsa_private_key_impl->info = &info;

    vscf_rsa_private_key_init_ctx(rsa_private_key_impl);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_init()'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_cleanup(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    if (rsa_private_key_impl == NULL || rsa_private_key_impl->info == NULL) {
        return;
    }

    vscf_rsa_private_key_release_hash(rsa_private_key_impl);
    vscf_rsa_private_key_release_random(rsa_private_key_impl);
    vscf_rsa_private_key_release_asn1rd(rsa_private_key_impl);
    vscf_rsa_private_key_release_asn1wr(rsa_private_key_impl);

    vscf_rsa_private_key_cleanup_ctx(rsa_private_key_impl);

    rsa_private_key_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_rsa_private_key_impl_t *
vscf_rsa_private_key_new(void) {

    vscf_rsa_private_key_impl_t *rsa_private_key_impl = (vscf_rsa_private_key_impl_t *) vscf_alloc(sizeof (vscf_rsa_private_key_impl_t));
    VSCF_ASSERT_ALLOC(rsa_private_key_impl);

    vscf_rsa_private_key_init(rsa_private_key_impl);

    rsa_private_key_impl->refcnt = 1;

    return rsa_private_key_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_new()'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_delete(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    if (rsa_private_key_impl && (--rsa_private_key_impl->refcnt == 0)) {
        vscf_rsa_private_key_cleanup(rsa_private_key_impl);
        vscf_dealloc(rsa_private_key_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_rsa_private_key_destroy(vscf_rsa_private_key_impl_t **rsa_private_key_impl_ref) {

    VSCF_ASSERT_PTR(rsa_private_key_impl_ref);

    vscf_rsa_private_key_impl_t *rsa_private_key_impl = *rsa_private_key_impl_ref;
    *rsa_private_key_impl_ref = NULL;

    vscf_rsa_private_key_delete(rsa_private_key_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_rsa_private_key_impl_t *
vscf_rsa_private_key_copy(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    // Proxy to the parent implementation.
    return (vscf_rsa_private_key_impl_t *)vscf_impl_copy((vscf_impl_t *)rsa_private_key_impl);
}

//
//  Return size of 'vscf_rsa_private_key_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_impl_size(void) {

    return sizeof (vscf_rsa_private_key_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_impl(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    return (vscf_impl_t *)(rsa_private_key_impl);
}

//
//  Setup dependency to the interface api 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_hash(vscf_rsa_private_key_impl_t *rsa_private_key_impl, const vscf_hash_api_t *hash) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT_PTR(rsa_private_key_impl->hash == NULL);

    rsa_private_key_impl->hash = hash;
}

//
//  Release dependency to the interface api 'hash'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_hash(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    rsa_private_key_impl->hash = NULL;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT_PTR(rsa_private_key_impl->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    rsa_private_key_impl->random = vscf_impl_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT_PTR(rsa_private_key_impl->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    rsa_private_key_impl->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    vscf_impl_destroy(&rsa_private_key_impl->random);
}

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1rd) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(asn1rd);
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1rd == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1rd));

    rsa_private_key_impl->asn1rd = vscf_impl_copy(asn1rd);
}

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1rd) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(asn1rd);
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1rd == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1rd));

    rsa_private_key_impl->asn1rd = asn1rd;
}

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    vscf_impl_destroy(&rsa_private_key_impl->asn1rd);
}

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1wr) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1wr == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1wr));

    rsa_private_key_impl->asn1wr = vscf_impl_copy(asn1wr);
}

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1wr) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1wr == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1wr));

    rsa_private_key_impl->asn1wr = asn1wr;
}

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    vscf_impl_destroy(&rsa_private_key_impl->asn1wr);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
