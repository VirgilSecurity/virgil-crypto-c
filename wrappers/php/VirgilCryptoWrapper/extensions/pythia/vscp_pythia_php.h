//
// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#ifndef VSCP_PYTHIA_PHP_H
#define VSCP_PYTHIA_PHP_H


#if defined(_WIN32) || defined(__CYGWIN__)
#   if defined(VSCP_PHP_INTERNAL_BUILD)
#       ifdef __GNUC__
#           define VSCP_PHP_PUBLIC __attribute__ ((dllexport))
#       else
#           define VSCP_PHP_PUBLIC __declspec(dllexport)
#       endif
#   else
#       ifdef __GNUC__
#           define VSCP_PHP_PUBLIC __attribute__ ((dllimport))
#       else
#           define VSCP_PHP_PUBLIC __declspec(dllimport)
#       endif
#   endif
#   define VSC_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define VSCP_PHP_PUBLIC __attribute__ ((visibility ("default")))
#       define VSCP_PHP_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSCP_PHP_PRIVATE
#   endif
#endif

//
// Constants
//

//
// Registered resources
//

#endif // VSCP_PYTHIA_PHP_H
