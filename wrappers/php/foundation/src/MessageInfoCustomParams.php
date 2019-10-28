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

class MessageInfoCustomParams
{

    /**
    * @var
    */
    private $ctx;

    const OF_INT_TYPE = 1;
    const OF_STRING_TYPE = 2;
    const OF_DATA_TYPE = 3;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_message_info_custom_params_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_message_info_custom_params_delete_php($this->ctx);
    }

    /**
    * Add custom parameter with integer value.
    *
    * @param string $key
    * @param int $value
    * @return void
    */
    public function addInt(string $key, int $value): void
    {
        vscf_message_info_custom_params_add_int_php($this->ctx, $key, $value);
    }

    /**
    * Add custom parameter with UTF8 string value.
    *
    * @param string $key
    * @param string $value
    * @return void
    */
    public function addString(string $key, string $value): void
    {
        vscf_message_info_custom_params_add_string_php($this->ctx, $key, $value);
    }

    /**
    * Add custom parameter with octet string value.
    *
    * @param string $key
    * @param string $value
    * @return void
    */
    public function addData(string $key, string $value): void
    {
        vscf_message_info_custom_params_add_data_php($this->ctx, $key, $value);
    }

    /**
    * Remove all parameters.
    *
    * @return void
    */
    public function clear(): void
    {
        vscf_message_info_custom_params_clear_php($this->ctx);
    }

    /**
    * Return custom parameter with integer value.
    *
    * @param string $key
    * @return int
    */
    public function findInt(string $key): int
    {
        return vscf_message_info_custom_params_find_int_php($this->ctx, $key);
    }

    /**
    * Return custom parameter with UTF8 string value.
    *
    * @param string $key
    * @return string
    */
    public function findString(string $key): string
    {
        return vscf_message_info_custom_params_find_string_php($this->ctx, $key);
    }

    /**
    * Return custom parameter with octet string value.
    *
    * @param string $key
    * @return string
    */
    public function findData(string $key): string
    {
        return vscf_message_info_custom_params_find_data_php($this->ctx, $key);
    }

    /**
    * Return true if at least one param exists.
    *
    * @return bool
    */
    public function hasParams(): bool
    {
        return vscf_message_info_custom_params_has_params_php($this->ctx);
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
