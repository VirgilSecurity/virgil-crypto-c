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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <virgil/crypto/foundation/vscf_alg_id.h>
#include <virgil/crypto/foundation/vscf_key_alg.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_key_alg_factory.h>
#include <virgil/crypto/foundation/vscf_key_asn1_serializer.h>
#include <virgil/crypto/foundation/vscf_pem.h>

const char k_error_msg_CRYPTO_INIT_FAILED[] = "Failed to initialize crypto engine.";
const char k_error_msg_CRYPTO_KEYGEN_FAILED[] = "Failed to generate private key.";
const char k_error_msg_CRYPTO_EXPORT_FAILED[] = "Failed to export private key or public key.";
const char k_error_msg_format_INVALID_KEY_ALG[] = "Given argument '%s' is not a valid key alg id.";
const char k_error_msg_format_INVALID_OPTION[] = "Given option '%s'.";

const char k_pem_title_PUBLIC_KEY[] = "PUBLIC KEY";
const char k_pem_title_PRIVATE_KEY[] = "PRIVATE KEY";


typedef enum {
    key_alg_id_NONE,
    key_alg_id_ED25519,
    key_alg_id_CURVE25519,
    key_alg_id_P256,
    key_alg_id_FALCON,
    key_alg_id_ROUND5,
    key_alg_id_CURVE25519_ED25519,
    key_alg_id_CURVE25519_ROUND5,
    key_alg_id_CURVE25519_ROUND5_FALCON,
    key_alg_id_CURVE25519_ROUND5_ED25519,
    key_alg_id_ED25519_FALCON,
    key_alg_id_CURVE25519_ROUND5_ED25519_FALCON
} key_alg_id_t;

void print_help(const char* prog_name) {
    printf("USAGE:\n");
    printf("    %s [<key_alg>]\n", prog_name);
    printf("OPTIONS:\n");
    printf("    <key_alg>:\n"
           "      - ed25519 (default)\n"
           "      - curve25519\n"
           "      - p256\n"
           "      - falcon\n"
           "      - round5\n"
           "      - curve25519_ed25519\n"
           "      - curve25519_round5\n"
           "      - curve25519_round5_falcon\n"
           "      - curve25519_round5_ed25519\n"
           "      - ed25519_falcon\n"
           "      - curve25519_round5_ed25519_falcon\n"
           );
}

void print_error(const char* msg) {
    fprintf(stderr, "<ERROR>: %s\n", msg);
}

void print_formatted_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "<ERROR>: ");
    vfprintf(stderr, format, args );
    va_end(args);
    fprintf(stderr, "\n");
}

void
print_bytes(const byte *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; ++i) {
        fprintf(stdout, "%02X", bytes[i]);
    }
    fprintf(stdout, "\r\n");
}

void
print_data(vsc_data_t data) {
    print_bytes(data.bytes, data.len);
}

void
print_buffer(vsc_buffer_t *buffer) {
    print_data(vsc_buffer_data(buffer));
}

bool is_option(const char* str) {
    const bool res = str[0] == '-' && str[1] == '-' && str[2] != '\0';
    return res;
}

key_alg_id_t convert_arg_to_key_alg_id(const char* arg) {

    if (strcmp(arg, "ed25519") == 0) {
        return key_alg_id_ED25519;

    } else if (strcmp(arg, "curve25519") == 0) {
        return key_alg_id_CURVE25519;

    } else if (strcmp(arg, "p256") == 0) {
        return key_alg_id_P256;

    } else if (strcmp(arg, "falcon") == 0) {
        return key_alg_id_FALCON;

    } else if (strcmp(arg, "round5") == 0) {
        return key_alg_id_ROUND5;

    } else if (strcmp(arg, "curve25519_ed25519") == 0) {
        return key_alg_id_CURVE25519_ED25519;

    } else if (strcmp(arg, "curve25519_round5") == 0) {
        return key_alg_id_CURVE25519_ROUND5;

    } else if (strcmp(arg, "curve25519_round5_falcon") == 0) {
        return key_alg_id_CURVE25519_ROUND5_FALCON;

    } else if (strcmp(arg, "curve25519_round5_ed25519") == 0) {
        return key_alg_id_CURVE25519_ROUND5_ED25519;

    } else if (strcmp(arg, "ed25519_falcon") == 0) {
        return key_alg_id_ED25519_FALCON;

    } else if (strcmp(arg, "curve25519_round5_ed25519_falcon") == 0) {
        return key_alg_id_CURVE25519_ROUND5_ED25519_FALCON;
    }

    return key_alg_id_NONE;
}

bool print_keypair(const char* key_alg_name, const vscf_impl_t *private_key) {

    vscf_impl_t *key_alg = NULL;
    vscf_impl_t *public_key = NULL;
    vscf_raw_public_key_t *raw_public_key = NULL;
    vscf_raw_private_key_t *raw_private_key = NULL;
    vscf_key_asn1_serializer_t *key_asn1_serializer = NULL;
    vsc_buffer_t *der_public_key = NULL;
    vsc_buffer_t *der_private_key = NULL;
    vsc_buffer_t *pem_public_key = NULL;
    vsc_buffer_t *pem_private_key = NULL;
    vscf_status_t status = vscf_status_SUCCESS;
    bool has_error = false;

    key_alg = vscf_key_alg_factory_create_from_key(private_key, NULL, NULL);
    if (NULL == key_alg) {
        goto error;
    }

    public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Get RAW keys.
    //
    raw_public_key = vscf_key_alg_export_public_key(key_alg, public_key, NULL);
    raw_private_key = vscf_key_alg_export_private_key(key_alg, private_key, NULL);

    if (NULL == raw_public_key || NULL == raw_private_key) {
        goto error;
    }

    //
    //  Get PKCS#8 keys.
    //
    key_asn1_serializer = vscf_key_asn1_serializer_new();
    vscf_key_asn1_serializer_setup_defaults(key_asn1_serializer);

    //
    // Export public key to DER format.
    //
    const size_t der_public_key_len =
            vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer, raw_public_key);

    der_public_key = vsc_buffer_new_with_capacity(der_public_key_len);

    status = vscf_key_asn1_serializer_serialize_public_key(key_asn1_serializer, raw_public_key, der_public_key);
    if (status != vscf_status_SUCCESS) {
        goto error;
    }

    //
    // Export public key to PEM format.
    //
    const size_t pem_public_key_len = vscf_pem_wrapped_len(k_pem_title_PUBLIC_KEY, vsc_buffer_len(der_public_key)) + 1;

    pem_public_key = vsc_buffer_new_with_capacity(pem_public_key_len);

    vscf_pem_wrap(k_pem_title_PUBLIC_KEY, vsc_buffer_data(der_public_key), pem_public_key);
    vsc_buffer_write_data(pem_public_key, vsc_data_from_str("\0", 1));

    //
    // Export private key to DER format.
    //
    const size_t der_private_key_len =
            vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer, raw_private_key);

    der_private_key = vsc_buffer_new_with_capacity(der_private_key_len);

    status = vscf_key_asn1_serializer_serialize_private_key(key_asn1_serializer, raw_private_key, der_private_key);
    if (status != vscf_status_SUCCESS) {
        goto error;
    }

    //
    // Export private key to PEM format.
    //
    const size_t pem_private_key_len = vscf_pem_wrapped_len(k_pem_title_PRIVATE_KEY, vsc_buffer_len(der_private_key)) + 1;

    pem_private_key = vsc_buffer_new_with_capacity(pem_private_key_len);

    vscf_pem_wrap(k_pem_title_PRIVATE_KEY, vsc_buffer_data(der_private_key), pem_private_key);
    vsc_buffer_write_data(pem_private_key, vsc_data_from_str("\0", 1));

    //
    //  Print ALL;
    //
    printf("KEY TYPE: %s\n\n", key_alg_name);

    printf("RAW PUBLIC KEY:\n");
    print_data(vscf_raw_public_key_data(raw_public_key));
    printf("\n");

    printf("RAW PRIVATE KEY:\n");
    print_data(vscf_raw_private_key_data(raw_private_key));
    printf("\n");

    printf("PKCS#8 DER PUBLIC KEY:\n");
    print_buffer(der_public_key);
    printf("\n");

    printf("PKCS#8 DER PRIVATE KEY:\n");
    print_buffer(der_private_key);
    printf("\n");

    printf("PKCS#8 PEM PUBLIC KEY:\n");
    printf("%s\n", (const char *)vsc_buffer_bytes(pem_public_key));
    printf("\n");

    printf("PKCS#8 PEM PRIVATE KEY:\n");
    printf("%s\n", (const char *)vsc_buffer_bytes(pem_private_key));
    printf("\n");

    has_error = false;
    goto end;

error:
    has_error = true;
    goto end;

end:
    vscf_impl_destroy(&key_alg);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_serializer_destroy(&key_asn1_serializer);
    vsc_buffer_destroy(&der_public_key);
    vsc_buffer_destroy(&der_private_key);
    vsc_buffer_destroy(&pem_public_key);
    vsc_buffer_destroy(&pem_private_key);

    return !has_error;
}

int main(int argc, const char *const *const argv) {

    const char* prog_name = argv[0] ? argv[0] : "generate_keypair";

    bool has_error = false;

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    const vscf_status_t init_status = vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *private_key = NULL;

    if (init_status != vscf_status_SUCCESS) {
        print_error(k_error_msg_CRYPTO_INIT_FAILED);
        goto error;
    }

    const char* key_alg_arg = (argc == 2) ? argv[1] : "ed25519";
    const key_alg_id_t key_alg_id = convert_arg_to_key_alg_id(key_alg_arg);

    switch(key_alg_id) {
    case key_alg_id_ED25519:
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, NULL);
        break;

    case key_alg_id_CURVE25519:
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_CURVE25519, NULL);
        break;

    case key_alg_id_P256:
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_SECP256R1, NULL);
        break;

    case key_alg_id_FALCON:
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_FALCON, NULL);
        break;

    case key_alg_id_ROUND5:
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ROUND5_ND_1CCA_5D, NULL);
        break;

    case key_alg_id_CURVE25519_ED25519:
        private_key = vscf_key_provider_generate_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, NULL);
        break;

    case key_alg_id_CURVE25519_ROUND5:
        private_key = vscf_key_provider_generate_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_1CCA_5D, NULL);
        break;

    case key_alg_id_CURVE25519_ROUND5_ED25519:
        private_key = vscf_key_provider_generate_compound_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_1CCA_5D,
                vscf_alg_id_ED25519, vscf_alg_id_NONE, NULL);
        break;

    case key_alg_id_CURVE25519_ROUND5_FALCON:
        private_key = vscf_key_provider_generate_compound_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_1CCA_5D,
                vscf_alg_id_FALCON, vscf_alg_id_NONE, NULL);
        break;

    case key_alg_id_ED25519_FALCON:
        private_key = vscf_key_provider_generate_hybrid_private_key(
                key_provider, vscf_alg_id_ED25519, vscf_alg_id_FALCON, NULL);
        break;

    case key_alg_id_CURVE25519_ROUND5_ED25519_FALCON:
        private_key = vscf_key_provider_generate_compound_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_1CCA_5D,
                vscf_alg_id_ED25519, vscf_alg_id_FALCON, NULL);
        break;

    case key_alg_id_NONE:
        print_formatted_error(k_error_msg_format_INVALID_KEY_ALG, key_alg_arg);
        goto error;
    }

    if (NULL == private_key) {
        print_error(k_error_msg_CRYPTO_KEYGEN_FAILED);
        goto error;
    }

    const bool print_ok = print_keypair(key_alg_arg, private_key);
    if (!print_ok) {
        print_error(k_error_msg_CRYPTO_EXPORT_FAILED);
        goto error;
    }


success:
    has_error = false;
    goto end;

error:
    has_error = true;
    goto end;

end:
    vscf_key_provider_destroy(&key_provider);

    if (has_error) {
        print_help(prog_name);
        return -1;
    }

    return 0;
}
