#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2019 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

option(VSCE_LIBRARY "Enable build of the 'phe' library" ON)
option(VSCE_MULTI_THREADING "Enable multi-threading safety for PHE library." ON)
option(VSCE_ERROR "Enable class 'error'." ON)
option(VSCE_PHE_COMMON "Enable class 'phe common'." ON)
option(VSCE_PHE_HASH "Enable class 'phe hash'." ON)
option(VSCE_PROOF_GENERATOR "Enable class 'proof generator'." ON)
option(VSCE_PROOF_VERIFIER "Enable class 'proof verifier'." ON)
option(VSCE_PHE_SERVER "Enable class 'phe server'." ON)
option(VSCE_PHE_CLIENT "Enable class 'phe client'." ON)
option(VSCE_PHE_CIPHER "Enable class 'phe cipher'." ON)
option(VSCE_UOKMS_CLIENT "Enable class 'uokms client'." ON)
option(VSCE_UOKMS_SERVER "Enable class 'uokms server'." ON)
option(VSCE_UOKMS_WRAP_ROTATION "Enable class 'uokms wrap rotation'." ON)
mark_as_advanced(
        VSCE_LIBRARY
        VSCE_MULTI_THREADING
        VSCE_ERROR
        VSCE_PHE_COMMON
        VSCE_PHE_HASH
        VSCE_PROOF_GENERATOR
        VSCE_PROOF_VERIFIER
        VSCE_PHE_SERVER
        VSCE_PHE_CLIENT
        VSCE_PHE_CIPHER
        VSCE_UOKMS_CLIENT
        VSCE_UOKMS_SERVER
        VSCE_UOKMS_WRAP_ROTATION
        )

if(VSCE_PHE_HASH AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_HASH depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_HASH AND NOT VSCF_HKDF)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_HASH depends on the feature:")
    message("     VSCF_HKDF - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_HASH AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_HASH depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PROOF_GENERATOR AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PROOF_GENERATOR depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PROOF_VERIFIER AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PROOF_VERIFIER depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_SERVER AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_SERVER depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_SERVER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_SERVER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CLIENT AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CLIENT depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CLIENT AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CLIENT depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CIPHER AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CIPHER depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CIPHER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CIPHER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CIPHER AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CIPHER depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CIPHER AND NOT VSCF_HKDF)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CIPHER depends on the feature:")
    message("     VSCF_HKDF - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_PHE_CIPHER AND NOT VSCF_AES256_GCM)
    message("-- error --")
    message("--")
    message("Feature VSCE_PHE_CIPHER depends on the feature:")
    message("     VSCF_AES256_GCM - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_CLIENT AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_CLIENT depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_CLIENT AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_CLIENT depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_CLIENT AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_CLIENT depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_CLIENT AND NOT VSCF_HKDF)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_CLIENT depends on the feature:")
    message("     VSCF_HKDF - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_CLIENT AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_CLIENT depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_SERVER AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_SERVER depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_SERVER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_SERVER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSCE_UOKMS_WRAP_ROTATION AND NOT VSCE_PHE_COMMON)
    message("-- error --")
    message("--")
    message("Feature VSCE_UOKMS_WRAP_ROTATION depends on the feature:")
    message("     VSCE_PHE_COMMON - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()
