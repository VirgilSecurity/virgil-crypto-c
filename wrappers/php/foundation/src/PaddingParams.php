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
* Handles padding parameters and constraints.
*/
class PaddingParams
{

    /**
    * @var
    */
    private $ctx;

    const DEFAULT_FRAME = 160;
    const DEFAULT_FRAME_MIN = 32;
    const DEFAULT_FRAME_MAX = 8 * 1024;

    /**
    * Build padding params with given constraints.
    * Precondition: frame_length_min <= frame_length <= frame_length_max.
    * Next formula can clarify what frame is: padding_length = data_length MOD frame
    *
    * @param int $frame
    * @param int $frameMin
    * @param int $frameMax
    * @return PaddingParams
    */
    public static function withConstraints(int $frame, int $frameMin, int $frameMax): PaddingParams
    {
        $ctx = vscf_padding_params_with_constraints_php($frame, $frameMin, $frameMax);
        return new PaddingParams($ctx);
    }

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_padding_params_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_padding_params_delete_php($this->ctx);
    }

    /**
    * Return padding frame in bytes.
    *
    * @return int
    */
    public function frame(): int
    {
        return vscf_padding_params_frame_php($this->ctx);
    }

    /**
    * Return minimum padding frame in bytes.
    *
    * @return int
    */
    public function frameMin(): int
    {
        return vscf_padding_params_frame_min_php($this->ctx);
    }

    /**
    * Return minimum padding frame in bytes.
    *
    * @return int
    */
    public function frameMax(): int
    {
        return vscf_padding_params_frame_max_php($this->ctx);
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
