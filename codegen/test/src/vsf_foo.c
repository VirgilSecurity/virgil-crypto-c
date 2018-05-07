//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_foo.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    //
    //  Constant that is defined out of a typed enum.
    //
    vsf_foo_INTEGRAL_C = 777
};

//
//  Enumeration type with private definition.
//
enum vsf_foo_bag_t {
    vsf_foo_bag_ONE = 1,
    vsf_foo_bag_TWO
};
typedef enum vsf_foo_bag_t vsf_foo_bag_t;

//
//  Structure with a private definition.
//
struct vsf_foo_secret_t {
    //
    //  Any type is a power of the C language.
    //
    const void* any;
};
typedef struct vsf_foo_secret_t vsf_foo_secret_t;

//
//  Global variable that conatins array of strings.
//  And defined somewhere else.
//
VSF_PUBLIC extern const char *const vsf_foo_external_features[];

//
//  Global variable that conatins derived size array of strings.
//
const char *const vsf_foo_features[] = {
    "This is a string 1",
    "This is a string 2"
};

//
//  Global variable that conatins array of any type.
//
static const void* private_api[];

//
//  Global variable that conatins any class.
//
static const void* self_api = private_api[0];

//
//  Private instantiation if the structure 'vsf_foo_context_t'
//
static const vsf_foo_context_t foo_context_inst = {
    1,
    255,
    255
};

//
//  Just do nothing.
//
VSF_PUBLIC void
vsf_foo_do_nothing (void) {

    //  Boo.
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


//
//  Public visibility.
//
VSF_PUBLIC void
vsf_foo_do_public (void) {
    //  TODO: This is STUB. Implement me.
}

//
//  Private visibility
//
VSF_PRIVATE void
vsf_foo_do_private (void) {
    //  TODO: This is STUB. Implement me.
}
