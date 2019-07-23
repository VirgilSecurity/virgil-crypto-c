//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
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
//  This class provides methods that accept and return special class "data".
//  Class "data" represents "readonly" byte array and should be wrapped to
//  a native byte array in a wrapper language.
// --------------------------------------------------------------------------

#ifndef CODEGEN_TEST_DATA_H_INCLUDED
#define CODEGEN_TEST_DATA_H_INCLUDED

#include "codegen_library.h"

#if !CODEGEN_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if CODEGEN_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#endif

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

//
//  Return length of given data.
//
CODEGEN_PUBLIC size_t
codegen_test_data_get_len(vsc_data_t data);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // CODEGEN_TEST_DATA_H_INCLUDED
//  @end
