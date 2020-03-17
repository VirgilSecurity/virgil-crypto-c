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
* Handles a list of "signer info" class objects.
*/
class SignerInfoList
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
        $this->ctx = is_null($ctx) ? vscf_signer_info_list_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_signer_info_list_delete_php($this->ctx);
    }

    /**
    * Return true if given list has item.
    *
    * @return bool
    */
    public function hasItem(): bool
    {
        return vscf_signer_info_list_has_item_php($this->ctx);
    }

    /**
    * Return list item.
    *
    * @return SignerInfo
    */
    public function item(): SignerInfo
    {
        $ctx = vscf_signer_info_list_item_php($this->ctx);
        return new SignerInfo($ctx);
    }

    /**
    * Return true if list has next item.
    *
    * @return bool
    */
    public function hasNext(): bool
    {
        return vscf_signer_info_list_has_next_php($this->ctx);
    }

    /**
    * Return next list node if exists, or NULL otherwise.
    *
    * @return SignerInfoList
    */
    public function next(): SignerInfoList
    {
        $ctx = vscf_signer_info_list_next_php($this->ctx);
        return new SignerInfoList($ctx);
    }

    /**
    * Return true if list has previous item.
    *
    * @return bool
    */
    public function hasPrev(): bool
    {
        return vscf_signer_info_list_has_prev_php($this->ctx);
    }

    /**
    * Return previous list node if exists, or NULL otherwise.
    *
    * @return SignerInfoList
    */
    public function prev(): SignerInfoList
    {
        $ctx = vscf_signer_info_list_prev_php($this->ctx);
        return new SignerInfoList($ctx);
    }

    /**
    * Remove all items.
    *
    * @return void
    */
    public function clear(): void
    {
        vscf_signer_info_list_clear_php($this->ctx);
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
