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


//  @description
// --------------------------------------------------------------------------
//  Interface 'hash stream' API.
// --------------------------------------------------------------------------

#ifndef VSCP_HASH_STREAM_API_H_INCLUDED
#define VSCP_HASH_STREAM_API_H_INCLUDED

#include "vscp_library.h"
#include "vscp_api.h"
#include "vscp_impl.h"
#include "vscp_hash_info.h"

#include <.(c_global_macros_project_common_namespace_dir)/vsc_data.h>
#include <.(c_global_macros_project_common_namespace_dir)/vsc_buffer.h>
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
//  Callback. Start a new hashing.
//
typedef void (*vscp_hash_stream_api_start_fn)(vscp_impl_t *impl);

//
//  Callback. Add given data to the hash.
//
typedef void (*vscp_hash_stream_api_update_fn)(vscp_impl_t *impl, vsc_data_t data);

//
//  Callback. Accompilsh hashing and return it's result (a message digest).
//
typedef void (*vscp_hash_stream_api_finish_fn)(vscp_impl_t *impl, vsc_buffer_t *digest);

//
//  Contains API requirements of the interface 'hash stream'.
//
struct vscp_hash_stream_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_stream' MUST be equal to the 'vscp_api_tag_HASH_STREAM'.
    //
    vscp_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscp_impl_tag_t impl_tag;
    //
    //  Link to the inherited interface API 'hash info'.
    //
    const vscp_hash_info_api_t *hash_info_api;
    //
    //  Start a new hashing.
    //
    vscp_hash_stream_api_start_fn start_cb;
    //
    //  Add given data to the hash.
    //
    vscp_hash_stream_api_update_fn update_cb;
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    vscp_hash_stream_api_finish_fn finish_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_HASH_STREAM_API_H_INCLUDED
//  @end
