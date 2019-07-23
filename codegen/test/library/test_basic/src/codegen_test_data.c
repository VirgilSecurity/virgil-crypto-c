//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  This class provides methods that accept and return special class "data".
//  Class "data" represents "readonly" byte array and should be wrapped to
//  a native byte array in a wrapper language.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "codegen_test_data.h"
#include "codegen_memory.h"
#include "codegen_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Return length of given data.
//
CODEGEN_PUBLIC size_t
codegen_test_data_get_len(vsc_data_t data) {

    CODEGEN_ASSERT(vsc_data_is_valid(data));

    return data.len;
}
