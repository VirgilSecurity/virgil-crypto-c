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
* Virgil implementation of the ECIES algorithm.
*/
class Ecies
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
        $this->ctx = is_null($ctx) ? vscf_ecies_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_ecies_delete_php($this->ctx);
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_ecies_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param Cipher $cipher
    * @return void
    */
    public function useCipher(Cipher $cipher): void
    {
        vscf_ecies_use_cipher_php($this->ctx, $cipher->getCtx());
    }

    /**
    * @param Mac $mac
    * @return void
    */
    public function useMac(Mac $mac): void
    {
        vscf_ecies_use_mac_php($this->ctx, $mac->getCtx());
    }

    /**
    * @param Kdf $kdf
    * @return void
    */
    public function useKdf(Kdf $kdf): void
    {
        vscf_ecies_use_kdf_php($this->ctx, $kdf->getCtx());
    }

    /**
    * @param PrivateKey $ephemeralKey
    * @return void
    */
    public function useEphemeralKey(PrivateKey $ephemeralKey): void
    {
        vscf_ecies_use_ephemeral_key_php($this->ctx, $ephemeralKey->getCtx());
    }

    /**
    * Set weak reference to the key algorithm.
    * Key algorithm MUST support shared key computation as well.
    *
    * @param KeyAlg $keyAlg
    * @return void
    */
    public function setKeyAlg(KeyAlg $keyAlg): void
    {
        vscf_ecies_set_key_alg_php($this->ctx, $keyAlg->getCtx());
    }

    /**
    * Release weak reference to the key algorithm.
    *
    * @return void
    */
    public function releaseKeyAlg(): void
    {
        vscf_ecies_release_key_alg_php($this->ctx);
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_ecies_setup_defaults_php($this->ctx);
    }

    /**
    * Setup predefined values to the uninitialized class dependencies
    * except random.
    *
    * @return void
    */
    public function setupDefaultsNoRandom(): void
    {
        vscf_ecies_setup_defaults_no_random_php($this->ctx);
    }

    /**
    * Calculate required buffer length to hold the encrypted data.
    *
    * @param PublicKey $publicKey
    * @param int $dataLen
    * @return int
    */
    public function encryptedLen(PublicKey $publicKey, int $dataLen): int
    {
        return vscf_ecies_encrypted_len_php($this->ctx, $publicKey->getCtx(), $dataLen);
    }

    /**
    * Encrypt data with a given public key.
    *
    * @param PublicKey $publicKey
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function encrypt(PublicKey $publicKey, string $data): string
    {
        return vscf_ecies_encrypt_php($this->ctx, $publicKey->getCtx(), $data);
    }

    /**
    * Calculate required buffer length to hold the decrypted data.
    *
    * @param PrivateKey $privateKey
    * @param int $dataLen
    * @return int
    */
    public function decryptedLen(PrivateKey $privateKey, int $dataLen): int
    {
        return vscf_ecies_decrypted_len_php($this->ctx, $privateKey->getCtx(), $dataLen);
    }

    /**
    * Decrypt given data.
    *
    * @param PrivateKey $privateKey
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function decrypt(PrivateKey $privateKey, string $data): string
    {
        return vscf_ecies_decrypt_php($this->ctx, $privateKey->getCtx(), $data);
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
