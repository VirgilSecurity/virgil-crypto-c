<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

require_once 'Alg.php';
require_once 'Hash.php';

/**
 * Class Sha256
 */
class Sha256 implements Alg, Hash
{
    /**
     * @var
     */
    private $c_ctx;

    const DIGEST_LEN = 32;
    const BLOCK_LEN = 64;

    /**
     * SHA256 constructor.
     * Allocate implementation context and perform it's initialization.
     * Postcondition: check memory allocation result.
     * @return void
     */
    public function __construct()
    {
        $this->c_ctx = vscf_sha256_new_php();
    }

    /**
     * SHA256 destructor.
     * Delete given implementation context and it's dependencies.
     * This is a reverse action of the function 'vscf_sha256_new()'.
     * @return void
     */
    public function __destruct()
    {
        vscf_sha256_delete_php($this->c_ctx);
    }

    /**
     * @return mixed
     */
    public function getCCtx()
    {
        return $this->c_ctx;
    }

    /**
     * Calculate hash over given data.
     * @param string $string
     * @return string
     */
    public function hash(string $string): string {
        return vscf_sha256_hash_php($string);
    }

    /**
     * Start a new hashing.
     * @return void
     */
    public function start() {
        vscf_sha256_start_php($this->c_ctx);
    }

    /**
     * Add given data to the hash.
     * @param string $string
     * @return void
     */
    public function update(string $string) {
        vscf_sha256_update_php($this->c_ctx, $string);
    }

    /**
     * Accompilsh hashing and return it's result (a message digest).
     * @return string
     */
    public function finish(): string {
        return vscf_sha256_finish_php($this->c_ctx);
    }
}