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
//  Provide interface to calculate hash (message digest) over a stream.
// --------------------------------------------------------------------------

#ifndef VSCP_HASH_STREAM_H_INCLUDED
#define VSCP_HASH_STREAM_H_INCLUDED

#include "vscp_library.h"
#include "vscp_error.h"
#include "vscp_impl.h"
#include "vscp_hash_info.h"
#include "vscp_api.h"

#include <virgil/common/vsc_data.h>
#include <virgil/common/vsc_buffer.h>
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
//  Contains API requirements of the interface 'hash stream'.
//
typedef struct vscp_hash_stream_api_t vscp_hash_stream_api_t;

//
//  Start a new hashing.
//
VSCP_PUBLIC void
vscp_hash_stream_start(vscp_impl_t *impl);

//
//  Add given data to the hash.
//
VSCP_PUBLIC void
vscp_hash_stream_update(vscp_impl_t *impl, vsc_data_t data);

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCP_PUBLIC void
vscp_hash_stream_finish(vscp_impl_t *impl, vsc_buffer_t *digest);

//
//  Return hash stream API, or NULL if it is not implemented.
//
VSCP_PUBLIC const vscp_hash_stream_api_t *
vscp_hash_stream_api(vscp_impl_t *impl);

//
//  Return hash info API.
//
VSCP_PUBLIC const vscp_hash_info_api_t *
vscp_hash_stream_hash_info_api(const vscp_hash_stream_api_t *hash_stream_api);

//
//  Check if given object implements interface 'hash stream'.
//
VSCP_PUBLIC bool
vscp_hash_stream_is_implemented(vscp_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCP_PUBLIC vscp_api_tag_t
vscp_hash_stream_api_tag(const vscp_hash_stream_api_t *hash_stream_api);

//
//  Returns implementation unique identifier.
//
VSCP_PUBLIC vscp_impl_tag_t
vscp_hash_stream_impl_tag(const vscp_hash_stream_api_t *hash_stream_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_HASH_STREAM_H_INCLUDED
//  @end
