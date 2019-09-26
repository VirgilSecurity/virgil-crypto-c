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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"


#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"

#include "test_data_deterministic_key.h"
#include "test_data_key_provider.h"
#include "test_data_ed25519.h"
#include "test_data_rsa.h"
#include "test_data_secp256r1.h"

// jmp_buf ebuf;
// void
// jump_handler(const char *message, const char *file, int line) {
//    VSCF_UNUSED(message);
//    VSCF_UNUSED(file);
//    VSCF_UNUSED(line);
//
//    longjmp(ebuf, 1);
//}
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // if (setjmp(ebuf) == 0)
    {
        vscf_error_t error;
        vscf_error_reset(&error);

        vscf_key_provider_t *key_provider = vscf_key_provider_new();
        if (vscf_key_provider_setup_defaults(key_provider) != vscf_status_SUCCESS) {
            return -1;
        }

        const vsc_data_t test_data = {data, size};

        vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, test_data, &error);


        vscf_impl_destroy(&private_key);
        vscf_key_provider_destroy(&key_provider);
    }
    // else
    {
        printf("=====================>\n");
        return -1;
    }
    return 0;
}
