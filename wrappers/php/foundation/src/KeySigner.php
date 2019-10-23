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
* Provide an interface for signing and verifying data digest
* with asymmetric keys.
*/
interface KeySigner extends Ctx
{

    /**
    * Check if algorithm can sign data digest with a given key.
    *
    * @param PrivateKey $privateKey
    * @return bool
    */
    public function canSign(PrivateKey $privateKey): bool
    ;

    /**
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    *
    * @param Key $key
    * @return int
    */
    public function signatureLen(Key $key): int
    ;

    /**
    * Sign data digest with a given private key.
    *
    * @param PrivateKey $privateKey
    * @param AlgId $hashId
    * @param string $digest
    * @return string
    * @throws \Exception
    */
    public function signHash(PrivateKey $privateKey, AlgId $hashId, string $digest): string
    ;

    /**
    * Check if algorithm can verify data digest with a given key.
    *
    * @param PublicKey $publicKey
    * @return bool
    */
    public function canVerify(PublicKey $publicKey): bool
    ;

    /**
    * Verify data digest with a given public key and signature.
    *
    * @param PublicKey $publicKey
    * @param AlgId $hashId
    * @param string $digest
    * @param string $signature
    * @return bool
    */
    public function verifyHash(PublicKey $publicKey, AlgId $hashId, string $digest, string $signature): bool
    ;
}
