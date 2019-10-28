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
* Create algorithms based on the given information.
*/
class AlgFactory
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
        $this->ctx = is_null($ctx) ? vscf_alg_factory_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_alg_factory_delete_php($this->ctx);
    }

    /**
    * Create algorithm that implements "hash stream" interface.
    *
    * @param AlgInfo $algInfo
    * @return Hash
    * @throws \Exception
    */
    public static function createHashFromInfo(AlgInfo $algInfo): Hash
    {
        $ctx = vscf_alg_factory_create_hash_from_info_php($algInfo->getCtx());
        return FoundationImplementation::wrapHash($ctx);
    }

    /**
    * Create algorithm that implements "mac stream" interface.
    *
    * @param AlgInfo $algInfo
    * @return Mac
    * @throws \Exception
    */
    public static function createMacFromInfo(AlgInfo $algInfo): Mac
    {
        $ctx = vscf_alg_factory_create_mac_from_info_php($algInfo->getCtx());
        return FoundationImplementation::wrapMac($ctx);
    }

    /**
    * Create algorithm that implements "kdf" interface.
    *
    * @param AlgInfo $algInfo
    * @return Kdf
    * @throws \Exception
    */
    public static function createKdfFromInfo(AlgInfo $algInfo): Kdf
    {
        $ctx = vscf_alg_factory_create_kdf_from_info_php($algInfo->getCtx());
        return FoundationImplementation::wrapKdf($ctx);
    }

    /**
    * Create algorithm that implements "salted kdf" interface.
    *
    * @param AlgInfo $algInfo
    * @return SaltedKdf
    * @throws \Exception
    */
    public static function createSaltedKdfFromInfo(AlgInfo $algInfo): SaltedKdf
    {
        $ctx = vscf_alg_factory_create_salted_kdf_from_info_php($algInfo->getCtx());
        return FoundationImplementation::wrapSaltedKdf($ctx);
    }

    /**
    * Create algorithm that implements "cipher" interface.
    *
    * @param AlgInfo $algInfo
    * @return Cipher
    * @throws \Exception
    */
    public static function createCipherFromInfo(AlgInfo $algInfo): Cipher
    {
        $ctx = vscf_alg_factory_create_cipher_from_info_php($algInfo->getCtx());
        return FoundationImplementation::wrapCipher($ctx);
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
