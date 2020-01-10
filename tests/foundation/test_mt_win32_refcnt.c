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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"

#include <windows.h>


#define TEST_DEPENDENCIES_AVAILABLE VSCF_SHA256 &&VSCF_SIGNER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_sha256.h"
#include "vscf_signer.h"

// --------------------------------------------------------------------------
DWORD WINAPI
impl_shallow_copy_delete(LPVOID ctx) {
    vscf_impl_t *impl = (vscf_impl_t *)ctx;

    for (size_t i = 0; i < 1000000; ++i) {
        (void)vscf_impl_shallow_copy(impl);
        vscf_impl_delete(impl);
    }

    return 0;
}

void
test__sha256__shallow_copy_delete_1000000_times_3_threads__no_crash(void) {
    vscf_sha256_t *sha256 = vscf_sha256_new();

    DWORD t1_id;
    HANDLE t1 = CreateThread(NULL, 0, impl_shallow_copy_delete, sha256, 0, &t1_id);

    DWORD t2_id;
    HANDLE t2 = CreateThread(NULL, 0, impl_shallow_copy_delete, sha256, 0, &t2_id);

    DWORD t3_id;
    HANDLE t3 = CreateThread(NULL, 0, impl_shallow_copy_delete, sha256, 0, &t3_id);

    WaitForSingleObject(t1, INFINITE);
    WaitForSingleObject(t2, INFINITE);
    WaitForSingleObject(t3, INFINITE);

    CloseHandle(t1);
    CloseHandle(t2);
    CloseHandle(t3);

    vscf_sha256_destroy(&sha256);
}

// --------------------------------------------------------------------------
DWORD WINAPI
signer_shallow_copy_delete(LPVOID ctx) {
    vscf_signer_t *signer = (vscf_signer_t *)ctx;

    for (size_t i = 0; i < 1000000; ++i) {
        (void)vscf_signer_shallow_copy(signer);
        vscf_signer_delete(signer);
    }

    return 0;
}

void
test__signer__shallow_copy_delete_1000000_times_3_threads__no_crash(void) {
    vscf_signer_t *signer = vscf_signer_new();

    DWORD t1_id;
    HANDLE t1 = CreateThread(NULL, 0, signer_shallow_copy_delete, signer, 0, &t1_id);

    DWORD t2_id;
    HANDLE t2 = CreateThread(NULL, 0, signer_shallow_copy_delete, signer, 0, &t2_id);

    DWORD t3_id;
    HANDLE t3 = CreateThread(NULL, 0, signer_shallow_copy_delete, signer, 0, &t3_id);

    WaitForSingleObject(t1, INFINITE);
    WaitForSingleObject(t2, INFINITE);
    WaitForSingleObject(t3, INFINITE);

    CloseHandle(t1);
    CloseHandle(t2);
    CloseHandle(t3);

    vscf_signer_destroy(&signer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__sha256__shallow_copy_delete_1000000_times_3_threads__no_crash);
    RUN_TEST(test__signer__shallow_copy_delete_1000000_times_3_threads__no_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
