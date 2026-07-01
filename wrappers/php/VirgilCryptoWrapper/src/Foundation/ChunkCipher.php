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

class ChunkCipher implements Alg, Encrypt, Decrypt, CipherInfo, Cipher
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
        $this->ctx = is_null($ctx) ? vscf_chunk_cipher_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_chunk_cipher_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_chunk_cipher_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_chunk_cipher_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgInfo
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_chunk_cipher_produce_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return void
    * @throws \Exception
    */
    public function restoreAlgInfo(AlgInfo $$algInfo): void
    {
        vscf_chunk_cipher_restore_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function encrypt(string $$data): string
    {
        return vscf_chunk_cipher_encrypt_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptedLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_encrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function preciseEncryptedLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_precise_encrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function decrypt(string $$data): string
    {
        return vscf_chunk_cipher_decrypt_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptedLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_decrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$nonce
    * @return void
    */
    public function setNonce(string $$nonce): void
    {
        vscf_chunk_cipher_set_nonce_php($this->ctx, $$nonce);
    }

    /**
    *
    * @param string $$key
    * @return void
    */
    public function setKey(string $$key): void
    {
        vscf_chunk_cipher_set_key_php($this->ctx, $$key);
    }

    /**
    *
    * @return void
    */
    public function startEncryption(): void
    {
        vscf_chunk_cipher_start_encryption_php($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function startDecryption(): void
    {
        vscf_chunk_cipher_start_decryption_php($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @return string
    */
    public function update(string $$data): string
    {
        return vscf_chunk_cipher_update_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function outLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptedOutLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_encrypted_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptedOutLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_decrypted_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finish(): string
    {
        return vscf_chunk_cipher_finish_php($this->ctx);
    }

    /**
    *
    * @param int $$chunkSize
    * @return void
    */
    public function setChunkSize(int $$chunkSize): void
    {
        vscf_chunk_cipher_set_chunk_size_php($this->ctx, $$chunkSize);
    }

    /**
    *
    * @return string
    */
    public function nonce(): string
    {
        return vscf_chunk_cipher_nonce_php($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function nonceLen(): int
    {
        return vscf_chunk_cipher_nonce_len_php($this->ctx);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptionOutLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_encryption_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function processEncryption(string $$data): string
    {
        return vscf_chunk_cipher_process_encryption_php($this->ctx, $$data);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishEncryption(): string
    {
        return vscf_chunk_cipher_finish_encryption_php($this->ctx);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptionOutLen(int $$dataLen): int
    {
        return vscf_chunk_cipher_decryption_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function processDecryption(string $$data): string
    {
        return vscf_chunk_cipher_process_decryption_php($this->ctx, $$data);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishDecryption(): string
    {
        return vscf_chunk_cipher_finish_decryption_php($this->ctx);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function chunkCount(int $$dataLen): int
    {
        return vscf_chunk_cipher_chunk_count_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$chunkIndex
    * @param bool $$isLast
    * @param string $$plaintext
    * @return string
    * @throws \Exception
    */
    public function encryptAt(int $$chunkIndex, bool $$isLast, string $$plaintext): string
    {
        return vscf_chunk_cipher_encrypt_at_php($this->ctx, $$chunkIndex, $$isLast, $$plaintext);
    }

    /**
    *
    * @param int $$chunkIndex
    * @param bool $$isLast
    * @param string $$frame
    * @return string
    * @throws \Exception
    */
    public function decryptAt(int $$chunkIndex, bool $$isLast, string $$frame): string
    {
        return vscf_chunk_cipher_decrypt_at_php($this->ctx, $$chunkIndex, $$isLast, $$frame);
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
