<?php
/**
* Copyright (C) 2015-2019 Virgil Security, Inc.
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

namespace Virgil\CryptoWrapper\Foundation;

/**
* Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
*/
class Base64
{

    /**
    * Calculate length in bytes required to hold an encoded base64 string.
    *
    * @param int $dataLen
    * @return int
    */
    public static function encodedLen(int $dataLen): int
    {
        return vscf_base64_encoded_len_php($dataLen);
    }

    /**
    * Encode given data to the base64 format.
    * Note, written buffer is NOT null-terminated.
    *
    * @param string $data
    * @return string
    */
    public static function encode(string $data): string
    {
        return vscf_base64_encode_php($data);
    }

    /**
    * Calculate length in bytes required to hold a decoded base64 string.
    *
    * @param int $strLen
    * @return int
    */
    public static function decodedLen(int $strLen): int
    {
        return vscf_base64_decoded_len_php($strLen);
    }

    /**
    * Decode given data from the base64 format.
    *
    * @param string $str
    * @return string
    * @throws \Exception
    */
    public static function decode(string $str): string
    {
        return vscf_base64_decode_php($str);
    }
}
