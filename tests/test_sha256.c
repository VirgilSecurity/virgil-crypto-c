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


#include "unity.h"

#include "vsf_hash.h"
#include "vsf_hash_stream.h"
#include "vsf_sha256.h"

#include <assert.h>
#include <string.h>


static size_t unhexify(const char *ibuf, byte *obuf)
{
    byte c, c2;
    size_t len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify(const byte *ibuf, size_t len, char *obuf)
{
   byte l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}


static void test_interface_hash (const char *expected_digest_hex, const char *data_hex) {

    byte digest[vsf_sha256_DIGEST_SIZE] = { 0x00 };
    byte expected_digest[vsf_sha256_DIGEST_SIZE] = { 0x00 };
    byte data[16];

    size_t data_len = unhexify (data_hex, data);
    size_t expected_digest_len = unhexify (expected_digest_hex, expected_digest);

    vsf_hash (vsf_sha256_hash_api (), data, data_len, digest, vsf_sha256_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (expected_digest, digest, vsf_sha256_DIGEST_SIZE);
}

static void test_interface_hash_stream (const char *expected_digest_hex, const char *data_hex) {
    vsf_impl_t *sha256 = vsf_sha256_impl (vsf_sha256_new ());

    byte digest[vsf_sha256_DIGEST_SIZE] = { 0x00 };
    byte expected_digest[vsf_sha256_DIGEST_SIZE] = { 0x00 };
    byte data[16];

    size_t data_len = unhexify (data_hex, data);
    size_t expected_digest_len = unhexify (expected_digest_hex, expected_digest);

    vsf_hash_stream_start (sha256);
    vsf_hash_stream_update (sha256, data, data_len);
    vsf_hash_stream_finish (sha256, digest, vsf_sha256_DIGEST_SIZE);

    vsf_impl_destroy (&sha256);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (expected_digest, digest, vsf_sha256_DIGEST_SIZE);
}


void test_interface_hash_with_vector_RFC1321_1 (void) {
    test_interface_hash ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    test_interface_hash ("68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b", "bd");
    test_interface_hash ("7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788", "5fd4");
}

void test_interface_hash_stream_with_vector_RFC1321_1 (void) {
    test_interface_hash_stream ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    test_interface_hash_stream ("68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b", "bd");
    test_interface_hash_stream ("7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788", "5fd4");
}


int main() {
    UNITY_BEGIN();

    RUN_TEST(test_interface_hash_with_vector_RFC1321_1);
    RUN_TEST(test_interface_hash_stream_with_vector_RFC1321_1);

    return UNITY_END();
}

