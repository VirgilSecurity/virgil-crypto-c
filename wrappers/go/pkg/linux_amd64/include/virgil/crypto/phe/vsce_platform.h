//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This file contains platform specific information that is known during compilation.
// --------------------------------------------------------------------------

#ifndef VSCE_PLATFORM_H_INCLUDED
#define VSCE_PLATFORM_H_INCLUDED

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

#ifndef VSCE_HAVE_ASSERT_H
#define VSCE_HAVE_ASSERT_H 1
#endif

#ifndef VSCE_HAVE_STDATOMIC_H
#define VSCE_HAVE_STDATOMIC_H 1
#endif

#ifndef VSCE_SHARED_LIBRARY
#define VSCE_SHARED_LIBRARY 0
#endif

#ifndef VSCE_MULTI_THREADING
#define VSCE_MULTI_THREADING 1
#endif

#ifndef VSCE_ERROR
#define VSCE_ERROR 1
#endif

#ifndef VSCE_PHE_COMMON
#define VSCE_PHE_COMMON 1
#endif

#ifndef VSCE_PHE_HASH
#define VSCE_PHE_HASH 1
#endif

#ifndef VSCE_PROOF_GENERATOR
#define VSCE_PROOF_GENERATOR 1
#endif

#ifndef VSCE_PHE_PROOF_GENERATOR
#define VSCE_PHE_PROOF_GENERATOR 1
#endif

#ifndef VSCE_PROOF_VERIFIER
#define VSCE_PROOF_VERIFIER 1
#endif

#ifndef VSCE_PHE_PROOF_VERIFIER
#define VSCE_PHE_PROOF_VERIFIER 1
#endif

#ifndef VSCE_PHE_SERVER
#define VSCE_PHE_SERVER 1
#endif

#ifndef VSCE_PHE_CLIENT
#define VSCE_PHE_CLIENT 1
#endif

#ifndef VSCE_PHE_CIPHER
#define VSCE_PHE_CIPHER 1
#endif

#ifndef VSCE_UOKMS_PROOF_GENERATOR
#define VSCE_UOKMS_PROOF_GENERATOR 1
#endif

#ifndef VSCE_UOKMS_PROOF_VERIFIER
#define VSCE_UOKMS_PROOF_VERIFIER 1
#endif

#ifndef VSCE_UOKMS_CLIENT
#define VSCE_UOKMS_CLIENT 1
#endif

#ifndef VSCE_UOKMS_SERVER
#define VSCE_UOKMS_SERVER 1
#endif

#ifndef VSCE_UOKMS_WRAP_ROTATION
#define VSCE_UOKMS_WRAP_ROTATION 1
#endif

//
//  Defines namespace include prefix for project 'common'.
//
#if !defined(VSCE_INTERNAL_BUILD)
#define VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#else
#define VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'foundation'.
//
#if !defined(VSCE_INTERNAL_BUILD)
#define VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#else
#define VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#endif


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PLATFORM_H_INCLUDED
//  @end
