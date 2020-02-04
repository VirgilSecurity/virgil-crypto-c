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
* Create a bridge between "raw keys" and algorithms that can import them.
*/
class KeyAlgFactory
{

    /**
    * Create a key algorithm based on an identifier.
    *
    * @param AlgId $algId
    * @param Random $random
    * @return KeyAlg
    * @throws \Exception
    */
    public static function createFromAlgId(AlgId $algId, Random $random): KeyAlg
    {
        $ctx = vscf_key_alg_factory_create_from_alg_id_php($algId->getValue(), $random->getCtx());
        return FoundationImplementation::wrapKeyAlg($ctx);
    }

    /**
    * Create a key algorithm correspond to a specific key.
    *
    * @param Key $key
    * @param Random $random
    * @return KeyAlg
    * @throws \Exception
    */
    public static function createFromKey(Key $key, Random $random): KeyAlg
    {
        $ctx = vscf_key_alg_factory_create_from_key_php($key->getCtx(), $random->getCtx());
        return FoundationImplementation::wrapKeyAlg($ctx);
    }

    /**
    * Create a key algorithm that can import "raw public key".
    *
    * @param RawPublicKey $publicKey
    * @param Random $random
    * @return KeyAlg
    * @throws \Exception
    */
    public static function createFromRawPublicKey(RawPublicKey $publicKey, Random $random): KeyAlg
    {
        $ctx = vscf_key_alg_factory_create_from_raw_public_key_php($publicKey->getCtx(), $random->getCtx());
        return FoundationImplementation::wrapKeyAlg($ctx);
    }

    /**
    * Create a key algorithm that can import "raw private key".
    *
    * @param RawPrivateKey $privateKey
    * @param Random $random
    * @return KeyAlg
    * @throws \Exception
    */
    public static function createFromRawPrivateKey(RawPrivateKey $privateKey, Random $random): KeyAlg
    {
        $ctx = vscf_key_alg_factory_create_from_raw_private_key_php($privateKey->getCtx(), $random->getCtx());
        return FoundationImplementation::wrapKeyAlg($ctx);
    }
}
