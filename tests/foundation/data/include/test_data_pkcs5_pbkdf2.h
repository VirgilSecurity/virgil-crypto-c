//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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


#include "vsc_data.h"

//
//  Test vectors are taken form: https://stackoverflow.com/a/5130543/1763487
//

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 1
//      dkLen = 20
//  Output:
//      DK = 12 0f b6 cf fc f8 b3 2c 43 e7 22 52 56 c4 f8 37 a8 65 48 c9
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_1_ITERATION_COUNT;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 2
//      dkLen = 20
//  Output:
//      DK = ae 4d 0c 95 af 6b 46 d3 2d 0a df f9 28 f0 6d d0 2a 30 3f 8e
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_2_ITERATION_COUNT;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 4096
//      dkLen = 20
//  Output:
//      DK = c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_3_ITERATION_COUNT;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 16777216
//      dkLen = 20
//  Output:
//      DK = cf 81 c6 6f e8 cf c0 4d 1f 31 ec b6 5d ab 40 89 f7 f1 79 e8
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_4_ITERATION_COUNT;

//
//  Input:
//      P = "passwordPASSWORDpassword" (24 octets)
//      S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
//      c = 4096
//      dkLen = 25
//  Output:
//      DK = 34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf
//       2b 17 34 7e bc 18 00 18 1c
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_5_ITERATION_COUNT;

//
//  Input:
//      P = "pass\0word" (9 octets)
//      S = "sa\0lt" (5 octets)
//      c = 4096
//      dkLen = 16
//  Output:
//      DK = 89 b6 9d 05 16 f8 29 89 3c 69 62 26 65 0a 86 87
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_6_ITERATION_COUNT;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 4096
//      dkLen = 100
//  Output:
//      DK = c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d
//           96 28 93 a0 01 ce 4e 11 a4 96 38 73 aa 98 13 4a
//           f7 ad 98 c1 b4 58 ce 3f d7 4c a3 5b eb a3 cd a7
//           b8 d1 03 8d 6a 87 07 1b 91 8f 83 74 05 f3 fe 77
//           28 ff e7 f0 97 6f c3 5d d8 2f c0 e5 e4 6c e9 ce
//           26 a7 88 b2 c7 d1 83 fa 5b f8 d9 60 7e ec d7 1d
//           01 b4 f1 19
//
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7_KEY;
extern const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7_SALT;
extern const size_t test_pkcs5_pbkdf2_VECTOR_7_ITERATION_COUNT;
