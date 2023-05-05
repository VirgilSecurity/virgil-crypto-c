<?php
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

namespace Virgil\CryptoWrapper\Phe;

/**
* Implements wrap rotation.
*/
class UokmsWrapRotation
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
        $this->ctx = is_null($ctx) ? vsce_uokms_wrap_rotation_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_uokms_wrap_rotation_delete_php($this->ctx);
    }

    /**
    * @param \Virgil\CryptoWrapper\Foundation\Random $operationRandom
    * @return void
    */
    public function useOperationRandom(\Virgil\CryptoWrapper\Foundation\Random $operationRandom): void
    {
        vsce_uokms_wrap_rotation_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * Setups dependencies with default values.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_uokms_wrap_rotation_setup_defaults_php($this->ctx);
    }

    /**
    * Sets update token. Should be called only once and before any other function
    *
    * @param string $updateToken
    * @return void
    * @throws \Exception
    */
    public function setUpdateToken(string $updateToken): void
    {
        vsce_uokms_wrap_rotation_set_update_token_php($this->ctx, $updateToken);
    }

    /**
    * Updates EnrollmentRecord using server's update token
    *
    * @param string $wrap
    * @return string
    * @throws \Exception
    */
    public function updateWrap(string $wrap): string
    {
        return vsce_uokms_wrap_rotation_update_wrap_php($this->ctx, $wrap);
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
