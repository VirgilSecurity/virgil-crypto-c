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

interface KeyCipher extends Ctx, KeyAlg
{

    /**
    *
    * @param PublicKey $$publicKey
    * @param int $$dataLen
    * @return bool
    */
    public function canEncrypt(PublicKey $$publicKey, int $$dataLen): bool
    {
        return ($this->ctx, $$publicKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param int $$dataLen
    * @return int
    */
    public function encryptedLen(PublicKey $$publicKey, int $$dataLen): int
    {
        return ($this->ctx, $$publicKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function encrypt(PublicKey $$publicKey, string $$data): string
    {
        return ($this->ctx, $$publicKey->getCtx(), $$data);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return bool
    */
    public function canDecrypt(PrivateKey $$privateKey, int $$dataLen): bool
    {
        return ($this->ctx, $$privateKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return int
    */
    public function decryptedLen(PrivateKey $$privateKey, int $$dataLen): int
    {
        return ($this->ctx, $$privateKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function decrypt(PrivateKey $$privateKey, string $$data): string
    {
        return ($this->ctx, $$privateKey->getCtx(), $$data);
    }

}
