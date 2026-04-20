<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

class Pem
{

    /**
    *
    * @param string $$title
    * @param int $$dataLen
    * @return int
    */
    public static function wrappedLen(string $$title, int $$dataLen): int
    {
        return vscf_pem_wrapped_len_php($$title, $$dataLen);
    }

    /**
    *
    * @param string $$title
    * @param string $$data
    * @return string
    */
    public static function wrap(string $$title, string $$data): string
    {
        return vscf_pem_wrap_php($$title, $$data);
    }

    /**
    *
    * @param int $$pemLen
    * @return int
    */
    public static function unwrappedLen(int $$pemLen): int
    {
        return vscf_pem_unwrapped_len_php($$pemLen);
    }

    /**
    *
    * @param string $$pem
    * @return string
    * @throws \Exception
    */
    public static function unwrap(string $$pem): string
    {
        return vscf_pem_unwrap_php($$pem);
    }

    /**
    *
    * @param string $$pem
    * @return string
    */
    public static function title(string $$pem): string
    {
        return vscf_pem_title_php($$pem);
    }

}
