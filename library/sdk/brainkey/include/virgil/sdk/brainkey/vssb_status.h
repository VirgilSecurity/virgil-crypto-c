//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  Defines the library status codes.
// --------------------------------------------------------------------------

#ifndef VSSB_STATUS_H_INCLUDED
#define VSSB_STATUS_H_INCLUDED

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
//  Defines the library status codes.
//
enum vssb_status_t {
    //
    //  No errors was occurred.
    //
    vssb_status_SUCCESS = 0,
    //
    //  Met internal inconsistency.
    //
    vssb_status_INTERNAL_ERROR = -1,
    //
    //  Given HTTP response body can not be parsed in an expected way.
    //
    vssb_status_HTTP_RESPONSE_PARSE_FAILED = -401,
    //
    //  Given HTTP response handles unexpected status code.
    //
    vssb_status_HTTP_RESPONSE_ERROR = -402,
    //
    //  Got HTTP response with a service error - internal server error - status code 500.
    //
    vssb_status_HTTP_SERVICE_ERROR_SERVER_INTERNAL_ERROR = 1000,
    //
    //  Got HTTP response with a service error - bad blinded point data - status code 400.
    //
    vssb_status_HTTP_SERVICE_ERROR_BAD_BLINDED_POINT_DATA = 1001,
    //
    //  Got HTTP response with a service error - invalid json - status code 400.
    //
    vssb_status_HTTP_SERVICE_ERROR_INVALID_JSON = 1002,
    //
    //  Got HTTP response with a service error - undefined error - status code 400.
    //
    vssb_status_HTTP_SERVICE_ERROR_UNDEFINED = 1999
};
#ifndef VSSB_STATUS_T_DEFINED
#define VSSB_STATUS_T_DEFINED
    typedef enum vssb_status_t vssb_status_t;
#endif // VSSB_STATUS_T_DEFINED


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSB_STATUS_H_INCLUDED
//  @end
