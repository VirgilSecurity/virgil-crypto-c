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

/**
* Error context.
* Can be used for sequential operations, i.e. parsers, to accumulate error.
* In this way operation is successful if all steps are successful, otherwise
* last occurred error code can be obtained.
*/
class Error
{
    private $ctx;

    /**
    * Create underlying C context.
    * @return void
    */
    public function __construct()
    {
        $this->ctx = vsce_error_new_php();
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destruct()
    {
        vsce_error_delete_php($this->ctx);
    }

    /**
    * Reset context to the "no error" state.
    * @return void
    */
    public function reset(): void
    {
        return vsce_error_reset_php($this->ctx);
    }

    /**
    * Update context with given status.
    * If status is "success" then do nothing.
    *
    * @return void
    */
    public function update(): void
    {
        return vsce_error_update_php($this->ctx);
    }

    /**
    * Return true if status is not "success".
    *
    * @return void
    */
    public function hasError(): void
    {
        return vsce_error_has_error_php($this->ctx);
    }

    /**
    * Return error code.
    *
    * @throws Exception
    * @return void
    */
    public function status(): void
    {
        return vsce_error_status_php($this->ctx);
    }
}
