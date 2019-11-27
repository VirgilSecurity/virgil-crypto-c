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


#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"
#include "vscf_fake_random.h"

#include "test_data_recipient_cipher.h"

// sign then encrypt with self signed ed25519 key recipient
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    //
    //  Prepare random.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    //
    //  Prepare recipients / signers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    vscf_status_t setup_defaults_status = vscf_key_provider_setup_defaults(key_provider);

    VSC_UNUSED(setup_defaults_status);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);

    vscf_status_t public_key_import_status = vscf_error_status(&error);

    VSC_UNUSED(public_key_import_status);

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    VSC_UNUSED(vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    VSC_UNUSED(vscf_recipient_cipher_add_signer(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key));

    //
    //  Encrypt.
    //

    vsc_data_t fuzzy_data = vsc_data(data, size);

    VSC_UNUSED(vscf_recipient_cipher_start_signed_encryption(recipient_cipher, size));

    size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
    size_t enc_msg_data_len = vscf_recipient_cipher_encryption_out_len(recipient_cipher, size * 10) +
                              vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *enc_msg_header = vsc_buffer_new_with_capacity(message_info_len);
    vsc_buffer_t *enc_msg_data = vsc_buffer_new_with_capacity(enc_msg_data_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg_header);

    VSC_UNUSED(vscf_recipient_cipher_process_encryption(recipient_cipher, fuzzy_data, enc_msg_data));
    VSC_UNUSED(vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg_data));

    size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
    vsc_buffer_t *enc_msg_footer = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);
    VSC_UNUSED(vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer));

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&enc_msg_footer);
    vsc_buffer_destroy(&enc_msg_data);
    vsc_buffer_destroy(&enc_msg_header);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);

    return 0;
}
