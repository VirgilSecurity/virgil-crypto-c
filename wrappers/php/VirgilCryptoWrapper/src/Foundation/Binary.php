<?php
/**
* Copyright (C) 2015-2020 Virgil Security, Inc.
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
* Contains utils for convertion from bytes to HEX and vice-versa.
*/
class Binary
{

    /**
    * Return buffer length enaugh to hold hexed data.
    *
    * @param int $dataLen
    * @return int
    */
    public static function toHexLen(int $dataLen): int
    {
        return vscf_binary_to_hex_len_php($dataLen);
    }

    /**
    * Converts byte array to hex.
    * Output length should be twice bigger then input.
    *
    * @param string $data
    * @return string
    */
    public static function toHex(string $data): string
    {
        return vscf_binary_to_hex_php($data);
    }

    /**
    * Return buffer length enaugh to hold unhexed data.
    *
    * @param int $hexLen
    * @return int
    */
    public static function fromHexLen(int $hexLen): int
    {
        return vscf_binary_from_hex_len_php($hexLen);
    }

    /**
    * Converts hex string to byte array.
    * Output length should be at least half of the input hex string.
    *
    * @param string $hexStr
    * @return string
    * @throws \Exception
    */
    public static function fromHex(string $hexStr): string
    {
        return vscf_binary_from_hex_php($hexStr);
    }
}
