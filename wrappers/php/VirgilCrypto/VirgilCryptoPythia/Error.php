<?php
/**
* Copyright (C) 2015-2018 Virgil Security Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

namespace Virgil\VirgilCryptoPythia;

/**
* Defines the library error codes.
*/
class PythiaError
{

    /**
    * This error should not be returned if assertions is enabled.
    */
    const BADARGUMENTS = -1;

    /**
    * Undrlying pythia library returns -1.
    */
    const PYTHIAINNERFAIL = -200;

    /**
    * Pythia verify operation failed.
    */
    const VERIFICATIONFAIL = -201;

    /**
    * Create enumeration value from the correspond C enumeration value.
    */
    public function __construct($error) {
        self.init(rawValue: Int(error.rawValue))!
    }

    /**
    * Check given C error (result), and if it's not "success" then throw correspond exception.
    */
    public static function handleError($code) {
        if $code !== vscp_SUCCESS {
            throw PythiaError($code)
        }
    }
}
