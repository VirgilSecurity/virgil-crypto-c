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

class RandomPadding implements Alg, Padding
{

    /**
    * @var
    */
    private $ctx;

    const PADDING_SIZE_LEN = 4;
    const PADDING_LEN_MIN = 5;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_random_padding_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_random_padding_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_random_padding_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_random_padding_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgInfo
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_random_padding_produce_alg_info_php($this->ctx);
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
        vscf_random_padding_restore_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param PaddingParams $$params
    * @return void
    */
    public function configure(PaddingParams $$params): void
    {
        vscf_random_padding_configure_php($this->ctx, $$params);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function paddedDataLen(int $$dataLen): int
    {
        return vscf_random_padding_padded_data_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @return int
    */
    public function len(): int
    {
        return vscf_random_padding_len_php($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function lenMax(): int
    {
        return vscf_random_padding_len_max_php($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function startDataProcessing(): void
    {
        vscf_random_padding_start_data_processing_php($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @return string
    */
    public function processData(string $$data): string
    {
        return vscf_random_padding_process_data_php($this->ctx, $$data);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishDataProcessing(): string
    {
        return vscf_random_padding_finish_data_processing_php($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function startPaddedDataProcessing(): void
    {
        vscf_random_padding_start_padded_data_processing_php($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @return string
    */
    public function processPaddedData(string $$data): string
    {
        return vscf_random_padding_process_padded_data_php($this->ctx, $$data);
    }

    /**
    *
    * @return int
    */
    public function finishPaddedDataProcessingOutLen(): int
    {
        return vscf_random_padding_finish_padded_data_processing_out_len_php($this->ctx);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishPaddedDataProcessing(): string
    {
        return vscf_random_padding_finish_padded_data_processing_php($this->ctx);
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
