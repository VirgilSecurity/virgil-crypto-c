//  Copyright (c) 2015-2018 Virgil Security Inc.
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

#include "vsf.h"

#include <stdio.h>

static void print_buf(const char *title, const unsigned char *buf, size_t buf_len)
{
    size_t i = 0;
    fprintf(stdout, "%s\n", title);
    for(i = 0; i < buf_len; ++i) {
        fprintf(stdout, "%02X%s", buf[i], (i + 1) % 16 == 0 ? "\r\n" : " ");
    }

}

int main (void) {
    uint8_t *digest = vsf_alloc (vsf_sha256_DIGEST_SIZE);
    uint8_t data[3] = {0x01, 0x02, 0x03};

    void* hash = (void *) vsf_sha256_new();


    vsf_buffer_use(hash, digest, vsf_sha256_DIGEST_SIZE);
    VSF_ASSERT (digest != NULL);

    vsf_hash_start (hash);
    vsf_hash_append (hash, data, sizeof(data));
    vsf_hash_append (hash, data, sizeof(data));
    vsf_hash_append (hash, data, sizeof(data));
    vsf_hash_finish (hash);


    print_buf ("SHA256", vsf_buffer_data (hash), vsf_buffer_used_size (hash));
    print_buf ("SHA256", digest, vsf_sha256_DIGEST_SIZE);

    vsf_destroy (&hash);
    vsf_dealloc (digest);
    return 0;
}
