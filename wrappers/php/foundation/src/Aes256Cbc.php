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

namespace Virgil\CryptoWrapper\Foundation;

/**
* Implementation of the symmetric cipher AES-256 bit in a CBC mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
class Aes256Cbc implements Alg, Encrypt, Decrypt, CipherInfo, Cipher
{

    /**
    * @var
    */
    private $ctx;

    const NONCE_LEN = 16;
    const KEY_LEN = 32;
    const KEY_BITLEN = 256;
    const BLOCK_LEN = 16;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_aes256_cbc_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_aes256_cbc_delete_php($this->ctx);
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_aes256_cbc_alg_id_php($this->ctx);
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
        $ctx = vscf_aes256_cbc_produce_alg_info_php($this->ctx);
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
        vscf_aes256_cbc_restore_alg_info_php($this->ctx, $algInfo->getCtx());
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
        return vscf_aes256_cbc_encrypt_php($this->ctx, $data);
    }

    /**
    * Calculate required buffer length to hold the encrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function encryptedLen(int $dataLen): int
    {
        return vscf_aes256_cbc_encrypted_len_php($this->ctx, $dataLen);
    }

    /**
    * Precise length calculation of encrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function preciseEncryptedLen(int $dataLen): int
    {
        return vscf_aes256_cbc_precise_encrypted_len_php($this->ctx, $dataLen);
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
        return vscf_aes256_cbc_decrypt_php($this->ctx, $data);
    }

    /**
    * Calculate required buffer length to hold the decrypted data.
    *
    * @param int $dataLen
    * @return int
    */
    public function decryptedLen(int $dataLen): int
    {
        return vscf_aes256_cbc_decrypted_len_php($this->ctx, $dataLen);
    }

    /**
    * Setup IV or nonce.
    *
    * @param string $nonce
    * @return void
    */
    public function setNonce(string $nonce): void
    {
        vscf_aes256_cbc_set_nonce_php($this->ctx, $nonce);
    }

    /**
    * Set cipher encryption / decryption key.
    *
    * @param string $key
    * @return void
    */
    public function setKey(string $key): void
    {
        vscf_aes256_cbc_set_key_php($this->ctx, $key);
    }

    /**
    * Start sequential encryption.
    *
    * @return void
    */
    public function startEncryption(): void
    {
        vscf_aes256_cbc_start_encryption_php($this->ctx);
    }

    /**
    * Start sequential decryption.
    *
    * @return void
    */
    public function startDecryption(): void
    {
        vscf_aes256_cbc_start_decryption_php($this->ctx);
    }

    /**
    * Process encryption or decryption of the given data chunk.
    *
    * @param string $data
    * @return string
    */
    public function update(string $data): string
    {
        return vscf_aes256_cbc_update_php($this->ctx, $data);
    }

    /**
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    *
    * @param int $dataLen
    * @return int
    */
    public function outLen(int $dataLen): int
    {
        return vscf_aes256_cbc_out_len_php($this->ctx, $dataLen);
    }

    /**
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    *
    * @param int $dataLen
    * @return int
    */
    public function encryptedOutLen(int $dataLen): int
    {
        return vscf_aes256_cbc_encrypted_out_len_php($this->ctx, $dataLen);
    }

    /**
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    *
    * @param int $dataLen
    * @return int
    */
    public function decryptedOutLen(int $dataLen): int
    {
        return vscf_aes256_cbc_decrypted_out_len_php($this->ctx, $dataLen);
    }

    /**
    * Accomplish encryption or decryption process.
    *
    * @return string
    * @throws \Exception
    */
    public function finish(): string
    {
        return vscf_aes256_cbc_finish_php($this->ctx);
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
