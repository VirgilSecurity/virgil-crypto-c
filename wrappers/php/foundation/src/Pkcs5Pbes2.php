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
* Virgil Security implementation of the PBES2 (RFC 8018) algorithm.
*/
class Pkcs5Pbes2 implements Alg, Encrypt, Decrypt
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
        $this->ctx = is_null($ctx) ? vscf_pkcs5_pbes2_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_pkcs5_pbes2_delete_php($this->ctx);
    }

    /**
    * @param SaltedKdf $kdf
    * @return void
    */
    public function useKdf(SaltedKdf $kdf): void
    {
        vscf_pkcs5_pbes2_use_kdf_php($this->ctx, $kdf->getCtx());
    }

    /**
    * @param Cipher $cipher
    * @return void
    */
    public function useCipher(Cipher $cipher): void
    {
        vscf_pkcs5_pbes2_use_cipher_php($this->ctx, $cipher->getCtx());
    }

    /**
    * Configure cipher with a new password.
    *
    * @param string $pwd
    * @return void
    */
    public function reset(string $pwd): void
    {
        vscf_pkcs5_pbes2_reset_php($this->ctx, $pwd);
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_pkcs5_pbes2_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Produce object with algorithm information and configuration parameters.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_pkcs5_pbes2_produce_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Restore algorithm configuration from the given object.
    *
    * @param AlgInfo $algInfo
    * @return void
    * @throws \Exception
    */
    public function restoreAlgInfo(AlgInfo $algInfo): void
    {
        vscf_pkcs5_pbes2_restore_alg_info_php($this->ctx, $algInfo->getCtx());
    }

    /**
    * Encrypt given data.
    *
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function encrypt(string $data): string
    {
        return vscf_pkcs5_pbes2_encrypt_php($this->ctx, $data);
    }

    /**
    * Calculate required buffer length to hold the encrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function encryptedLen(int $dataLen): int
    {
        return vscf_pkcs5_pbes2_encrypted_len_php($this->ctx, $dataLen);
    }

    /**
    * Precise length calculation of encrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function preciseEncryptedLen(int $dataLen): int
    {
        return vscf_pkcs5_pbes2_precise_encrypted_len_php($this->ctx, $dataLen);
    }

    /**
    * Decrypt given data.
    *
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function decrypt(string $data): string
    {
        return vscf_pkcs5_pbes2_decrypt_php($this->ctx, $data);
    }

    /**
    * Calculate required buffer length to hold the decrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function decryptedLen(int $dataLen): int
    {
        return vscf_pkcs5_pbes2_decrypted_len_php($this->ctx, $dataLen);
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
