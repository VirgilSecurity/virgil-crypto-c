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


#include "vsc_data.h"

const byte MESSAGE_SHA512_DIGEST[] = {
    0x6d, 0x49, 0xd5, 0xe3, 0x4a, 0xd7, 0xa0, 0x35,
    0x9f, 0xb0, 0x06, 0x28, 0xaa, 0xcd, 0x41, 0xda,
    0x3c, 0x62, 0x34, 0x1e, 0xf2, 0x04, 0x00, 0x8e,
    0xa8, 0x7d, 0x40, 0x72, 0x9a, 0xa5, 0xfb, 0xd8,
    0x1c, 0xc1, 0x80, 0x97, 0x62, 0xa8, 0x05, 0x11,
    0x85, 0x26, 0x4d, 0xb0, 0x94, 0x04, 0x4e, 0xf8,
    0xe1, 0x2c, 0x4b, 0x27, 0x78, 0x1d, 0xe5, 0x58,
    0xf3, 0x97, 0xda, 0xa2, 0x07, 0x8c, 0x56, 0x8d,
};

const vsc_data_t test_key_provider_MESSAGE_SHA512_DIGEST = {
    MESSAGE_SHA512_DIGEST, sizeof(MESSAGE_SHA512_DIGEST)
};

const char test_bad_PRIVATE_KEY_PKCS8_PEM_BAD_STR[] = {
        "MIIB4QIBADCCAT8GCSqGSIb3DQEHA6CCATAwggEsAgECMYH+MIH7AgECoAoECEMoiy2L/B1oMAUGAytlcASB4jCB3wIBADAqMAUGAytlcAMhANuNm+oTawFCyBg+WSFkyT39KKcF4H+c+Cs6xz7QeQBwMBgGByiBjHECBQIwDQYJYIZIAWUDBAICBQAwQTANBglghkgBZQMEAgIFAAQw5NBsLcLbYdRkxTqKKWCLd8bkChN2b3ouj066qZoJ7ShIq62/J6bY7ks7YeEZKCcHMFEwHQYJYIZIAWUDBAEqBBDudjPh7qatkDijeQNw0uxyBDBJjFXVI+GPVhGxf2Ov5LnUQoSJhVkE5rQ1a5WybdmAJas9QDBovqh/5hVe+DciyaAwJgYJKoZIhvcNAQcBMBkGCWCGSAFlAwQBLgQMou3RXvIrIh3WD4GXoIGYMYGVMCMMFVZJUkdJTC1EQVRBLVNJR05FUi1JRKIKBAhDKIsti/wdaDBuDBVWSVJHSUwtREFUQS1TSUdOQVRVUkWiVQRTMFEwDQYJYIZIAWUDBAIDBQAEQJzSCzxISGQwdUtGCwpRoWm4fef9qPL3C8txkgxg0Iwik2mHpbaAz/CrqSWJDM3WQ5gMBRXDTD55mo9XiGt+1QkLeIgVeOr4UFPJEeEdUXpeKDpyK0EDWerKoxwQ/SYrPmYifwMeQcAgYK2DiNrN05kNTfC04EfwNIisWKWdAdU9"
};

const vsc_data_t test_bad_PRIVATE_KEY_BAD_PKCS8_PEM = {
        (const byte *)test_bad_PRIVATE_KEY_PKCS8_PEM_BAD_STR, sizeof(test_bad_PRIVATE_KEY_PKCS8_PEM_BAD_STR) - 1
};

