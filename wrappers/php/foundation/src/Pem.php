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

namespace VirgilCrypto\Foundation;

/**
* Simple PEM wrapper.
*/
class Pem
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_pem_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_pem_delete_php($this->ctx);
    }

    /**
    * Return length in bytes required to hold wrapped PEM format.
    *
    * @param string $title
    * @param int $dataLen
    * @return int
    */
    public static function wrappedLen(string $title, int $dataLen): int
    {
        return vscf_pem_wrapped_len_php($title, $dataLen);
    }

    /**
    * Takes binary data and wraps it to the simple PEM format - no
    * additional information just header-base64-footer.
    * Note, written buffer is NOT null-terminated.
    *
    * @param string $title
    * @param string $data
    * @return string
    */
    public static function wrap(string $title, string $data): string
    {
        return vscf_pem_wrap_php($title, $data);
    }

    /**
    * Return length in bytes required to hold unwrapped binary.
    *
    * @param int $pemLen
    * @return int
    */
    public static function unwrappedLen(int $pemLen): int
    {
        return vscf_pem_unwrapped_len_php($pemLen);
    }

    /**
    * Takes PEM data and extract binary data from it.
    *
    * @param string $pem
    * @return string
    * @throws \Exception
    */
    public static function unwrap(string $pem): string
    {
        return vscf_pem_unwrap_php($pem);
    }

    /**
    * Returns PEM title if PEM data is valid, otherwise - empty data.
    *
    * @param string $pem
    * @return string
    */
    public static function title(string $pem): string
    {
        return vscf_pem_title_php($pem);
    }

    /**
    * Get C context.
    *
    * @return resource
    */
    public function getCtx()
    {
        return $this->ctx;
    }
}
