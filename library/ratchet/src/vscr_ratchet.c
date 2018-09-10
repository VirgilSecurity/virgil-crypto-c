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

#include "vscr_ratchet.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <virgil/foundation/vscf_error_ctx.h>
//  @end


#include <virgil/common/private/vsc_buffer_defs.h>


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const uint8_t olm_chain_key_seed[] = {
    0x02
};

static const uint8_t olm_message_key_seed[] = {
    0x01
};

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_new(void) {

    vscr_ratchet_t *ratchet_ctx = (vscr_ratchet_t *) vscr_alloc(sizeof (vscr_ratchet_t));
    VSCR_ASSERT_ALLOC(ratchet_ctx);

    vscr_ratchet_init(ratchet_ctx);

    ratchet_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_ctx;
}

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_delete(vscr_ratchet_t *ratchet_ctx) {

    if (NULL == ratchet_ctx) {
        return;
    }

    vscr_ratchet_cleanup(ratchet_ctx);

    if (ratchet_ctx->self_dealloc_cb != NULL) {
         ratchet_ctx->self_dealloc_cb(ratchet_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_destroy(vscr_ratchet_t **ratchet_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_ctx_ref);

    vscr_ratchet_t *ratchet_ctx = *ratchet_ctx_ref;
    *ratchet_ctx_ref = NULL;

    vscr_ratchet_delete(ratchet_ctx);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_init(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    //  TODO: This is STUB. Implement me.
}

//
//  Release all inner resources.
//
VSCR_PUBLIC void
vscr_ratchet_cleanup(vscr_ratchet_t *ratchet_ctx) {

    //  TODO: This is STUB. Implement me.
    vscr_olm_sender_chain_destroy(&ratchet_ctx->sender_chain);
}

VSCR_PUBLIC void
vscr_ratchet_advance_root_chain(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vsc_buffer_t *secret = vsc_buffer_new_with_capacity(vscr_ratchet_OLM_SHARED_KEY_LENGTH);
    //  TODO: secret = Curve25519DH(ratchet_ctx->sender_chain->ratchet_private_key, ratchet_ctx->receiver_chains->value->ratchet_public_key)

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hmac_stream(hkdf, vscf_hmac256_impl(vscf_hmac256_new()));

    vsc_buffer_t *derived_secret = vsc_buffer_new_with_capacity(2 * vscr_ratchet_OLM_SHARED_KEY_LENGTH);
    vscf_hkdf_derive(hkdf,
                     vsc_buffer_ptr(secret), vsc_buffer_len(secret),
                     vsc_buffer_ptr(ratchet_ctx->root_key), vsc_buffer_len(ratchet_ctx->root_key),
                     ratchet_ctx->kdf_info->ratchet_info.bytes, ratchet_ctx->kdf_info->ratchet_info.len,
                     vsc_buffer_ptr(derived_secret), vsc_buffer_len(derived_secret));

    vsc_buffer_delete(ratchet_ctx->root_key);

    // FIXME
    ratchet_ctx->root_key->bytes = derived_secret->bytes;
    ratchet_ctx->root_key->len = vscr_ratchet_OLM_SHARED_KEY_LENGTH;
    ratchet_ctx->root_key->capacity = vscr_ratchet_OLM_SHARED_KEY_LENGTH;

    ratchet_ctx->sender_chain->chain_key->key->bytes = derived_secret->bytes + vscr_ratchet_OLM_SHARED_KEY_LENGTH;
    ratchet_ctx->sender_chain->chain_key->key->len = vscr_ratchet_OLM_SHARED_KEY_LENGTH;
    ratchet_ctx->sender_chain->chain_key->key->capacity = vscr_ratchet_OLM_SHARED_KEY_LENGTH;
    ratchet_ctx->sender_chain->chain_key->index = 0;

    vscf_hkdf_destroy(&hkdf);
    vsc_buffer_destroy(&secret);
}

VSCR_PUBLIC void
vscr_ratchet_create_message_key(vscr_ratchet_t *ratchet_ctx, vscr_olm_message_key_t *message_key) {

    vscf_hmac256_impl_t *hmac256= vscf_hmac256_new();

    vscf_hmac256_hmac(vsc_buffer_ptr(ratchet_ctx->sender_chain->chain_key->key),
                      vsc_buffer_len(ratchet_ctx->sender_chain->chain_key->key),
                      olm_message_key_seed,
                      sizeof(olm_message_key_seed),
                      message_key->key->bytes, message_key->key->len);

    message_key->index = ratchet_ctx->sender_chain->chain_key->index;

    vscf_hmac256_destroy(&hmac256);
}

VSCR_PUBLIC void
vscr_ratchet_advance_chain_key(vscr_olm_chain_key_t *chain_key) {

    VSCR_ASSERT(vsc_buffer_len(chain_key->key) == vscr_ratchet_OLM_SHARED_KEY_LENGTH);

    vscf_hmac256_impl_t *hmac256 = vscf_hmac256_new();

    vscf_hmac256_hmac(vsc_buffer_ptr(chain_key->key), vsc_buffer_len(chain_key->key),
                      olm_chain_key_seed, sizeof(olm_chain_key_seed),
                      vsc_buffer_ptr(chain_key->key), vsc_buffer_len(chain_key->key));

    chain_key->index += 1;

    vscf_hmac256_destroy(&hmac256);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_encrypt(vscr_ratchet_t *ratchet_ctx, vsc_data_t plain_text, vsc_buffer_t *cipher_text) {

    VSCR_UNUSED(ratchet_ctx);
    VSCR_UNUSED(plain_text);
    VSCR_UNUSED(cipher_text);

    if (!ratchet_ctx->sender_chain) {
        //  TODO: Generate Curve25519 ratchet key
        ratchet_ctx->sender_chain->ratchet_private_key = vsc_data(NULL, 0);

        vscr_ratchet_advance_root_chain(ratchet_ctx);
    }

    vscr_olm_message_key_t *message_key = vscr_olm_message_key_new();

    vscr_ratchet_create_message_key(ratchet_ctx, message_key);
    vscr_ratchet_advance_chain_key(ratchet_ctx->sender_chain->chain_key);

    //  TODO: Encrypt message
    //  TODO: Serialize message

    vscr_olm_message_key_destroy(&message_key);

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_decrypt(vscr_ratchet_t *ratchet_ctx, vsc_data_t cipher_text, vsc_buffer_t *plain_text) {

    VSCR_UNUSED(ratchet_ctx);
    VSCR_UNUSED(cipher_text);
    VSCR_UNUSED(plain_text);
    //  TODO: This is STUB. Implement me.

    return vscr_SUCCESS;
}
