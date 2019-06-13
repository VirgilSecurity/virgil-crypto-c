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

/**
 * Class SHA256
 */
class SHA256 implements Alg, Hash
{
    /**
     * @var
     */
    private $hashCtx;

    //
    //  Allocate implementation context and perform it's initialization.
    //  Postcondition: check memory allocation result.
    //
    /**
     * SHA256 constructor.
     */
    public function __construct()
    {
        $this->hashCtx = vscf_sha256_new_php();
    }

    //
    //  Destroy given implementation context and it's dependencies.
    //  This is a reverse action of the function 'vscf_sha256_new()'.
    //  Given reference is nullified.
    //
    /**
     * SHA256 destructor.
     */
    public function __destruct()
    {
        vscf_sha256_destroy_php($this->hashCtx);
    }

    //
    //  Return size of 'vscf_sha256_t' type.
    //
    /**
     * @return mixed
     */
    public function implSize() {
        return vscf_sha256_impl_size_php(); // ! void
    }

    //
    //  Cast to the 'vscf_impl_t' type.
    //
    /**
     * @return mixed
     */
    public function impl() {
        return vscf_sha256_impl_php($this->hashCtx);
    }

    //
    //  Perform initialization of preallocated implementation context.
    //
    /**
     * @return mixed
     */
    public function init() {
        return vscf_sha256_init_php($this->hashCtx);
    }

    //
    //  Cleanup implementation context and release dependencies.
    //  This is a reverse action of the function 'vscf_sha256_init()'.
    //
    /**
     * @return mixed
     */
    public function cleanup() {
        return vscf_sha256_cleanup_php($this->hashCtx);
    }

    //
    //  Delete given implementation context and it's dependencies.
    //  This is a reverse action of the function 'vscf_sha256_new()'.
    //
    /**
     * @return mixed
     */
    public function delete() {
        return vscf_sha256_delete_php($this->hashCtx);
    }

    //
    //  Copy given implementation context by increasing reference counter.
    //  If deep copy is required interface 'clonable' can be used.
    //
    /**
     * @return mixed
     */
    public function shallowCopy() {
        return vscf_sha256_shallow_copy_php($this->hashCtx);
    }

    //
    //  Provide algorithm identificator.
    //
    /**
     * @return mixed
     */
    public function algId() {
        return vscf_sha256_alg_id_php($this->hashCtx); // ! const vscf_sha256_t *self
    }

    //
    //  Produce object with algorithm information and configuration parameters.
    //
    /**
     * @return mixed
     */
    public function produceAlgInfo() {
        return vscf_sha256_produce_alg_info_php($this->hashCtx); // ! const vscf_sha256_t *self
    }

    //
    //  Restore algorithm configuration from the given object.
    //
    /**
     * @return mixed
     */
    public function restoreAlgInfo() {
        return vscf_sha256_restore_alg_info_php($this->hashCtx); // ! vscf_sha256_t *self, const vscf_impl_t *alg_info) VSCF_NODISCARD;
    }

    //
    //  Calculate hash over given data.
    //
    /**
     * @return string
     */
    public function hash(): string {
        return vscf_sha256_hash_php($this->hashCtx); // ! vsc_data_t data, vsc_buffer_t *digest
    }

    //
    //  Start a new hashing.
    //
    /**
     * @return mixed
     */
    public function start() {
        return vscf_sha256_start_php($this->hashCtx);
    }

    //
    //  Add given data to the hash.
    //
    /**
     * @return mixed
     */
    public function update() {
        return vscf_sha256_update_php($this->hashCtx); // ! vscf_sha256_t *self, vsc_data_t data
    }

    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    /**
     * @return string
     */
    public function finish(): string {
        return vscf_sha256_finish_php($this->hashCtx); // ! vscf_sha256_t *self, vsc_buffer_t *digest
    }

}