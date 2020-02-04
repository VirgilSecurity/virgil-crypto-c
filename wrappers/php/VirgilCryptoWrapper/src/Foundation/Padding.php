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
* Provide an interface to add and remove data padding.
*/
interface Padding extends Ctx
{

    /**
    * Set new padding parameters.
    *
    * @param PaddingParams $params
    * @return void
    */
    public function configure(PaddingParams $params): void;

    /**
    * Return length in bytes of a data with a padding.
    *
    * @param int $dataLen
    * @return int
    */
    public function paddedDataLen(int $dataLen): int;

    /**
    * Return an actual number of padding in bytes.
    * Note, this method might be called right before "finish data processing".
    *
    * @return int
    */
    public function len(): int;

    /**
    * Return a maximum number of padding in bytes.
    *
    * @return int
    */
    public function lenMax(): int;

    /**
    * Prepare the algorithm to process data.
    *
    * @return void
    */
    public function startDataProcessing(): void;

    /**
    * Only data length is needed to produce padding later.
    * Return data that should be further proceeded.
    *
    * @param string $data
    * @return string
    */
    public function processData(string $data): string;

    /**
    * Accomplish data processing and return padding.
    *
    * @return string
    * @throws \Exception
    */
    public function finishDataProcessing(): string;

    /**
    * Prepare the algorithm to process padded data.
    *
    * @return void
    */
    public function startPaddedDataProcessing(): void;

    /**
    * Process padded data.
    * Return filtered data without padding.
    *
    * @param string $data
    * @return string
    */
    public function processPaddedData(string $data): string;

    /**
    * Return length in bytes required hold output of the method
    * "finish padded data processing".
    *
    * @return int
    */
    public function finishPaddedDataProcessingOutLen(): int;

    /**
    * Accomplish padded data processing and return left data without a padding.
    *
    * @return string
    * @throws \Exception
    */
    public function finishPaddedDataProcessing(): string;
}
