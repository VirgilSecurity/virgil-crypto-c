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
* Handle hashed based algorithm information, i.e. HKDF, HMAC, etc.
*/
class HashBasedAlgInfo implements AlgInfo
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Create algorithm info with identificator and HASH algorithm info.
    *
    * @param AlgId $algId
    * @param AlgInfo $hashAlgInfo
    * @return HashBasedAlgInfo
    */
    public static function withMembers(AlgId $algId, AlgInfo $hashAlgInfo): HashBasedAlgInfo
    {
        $ctx = vscf_hash_based_alg_info_with_members_php($algId, $hashAlgInfo);
        return new HashBasedAlgInfo($ctx);
    }

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_hash_based_alg_info_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_hash_based_alg_info_delete_php($this->ctx);
    }

    /**
    * Return hash algorithm information.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function hashAlgInfo(): AlgInfo
    {
        $ctx = vscf_hash_based_alg_info_hash_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_hash_based_alg_info_alg_id_php($this->ctx);
        return new AlgId($enum);
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