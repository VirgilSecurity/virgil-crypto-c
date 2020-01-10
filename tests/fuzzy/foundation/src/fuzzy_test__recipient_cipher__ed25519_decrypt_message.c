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


#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"
#include "vscf_fake_random.h"

#include "test_data_recipient_cipher.h"


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    //
    //  Prepare decryption key.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t setup_defaults_status = vscf_key_provider_setup_defaults(key_provider);

    VSC_UNUSED(setup_defaults_status);

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);

    //
    //  Decrypt.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();


    vsc_buffer_t *dec_msg =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher, size * 10) +
                                         vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    vscf_status_t start_decryption_status = vscf_recipient_cipher_start_decryption_with_key(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty());
    VSC_UNUSED(start_decryption_status);

    vsc_data_t data_wrapper = vsc_data(data, size);
    vscf_status_t process_decryption_status =
            vscf_recipient_cipher_process_decryption(recipient_cipher, data_wrapper, dec_msg);

    VSC_UNUSED(process_decryption_status);

    vscf_status_t finish_decryption_status = vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg);
    VSC_UNUSED(finish_decryption_status);

    vsc_buffer_destroy(&dec_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    return 0;
}
