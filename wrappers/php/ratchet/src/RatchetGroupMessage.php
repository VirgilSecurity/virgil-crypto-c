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

namespace Virgil\CryptoWrapper\Ratchet;

/**
* Class represents ratchet group message
*/
class RatchetGroupMessage
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
        $this->ctx = is_null($ctx) ? vscr_ratchet_group_message_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscr_ratchet_group_message_delete_php($this->ctx);
    }

    /**
    * Returns message type.
    *
    * @return GroupMsgType
    */
    public function getType(): GroupMsgType
    {
        $enum = vscr_ratchet_group_message_get_type_php($this->ctx);
        return new GroupMsgType($enum);
    }

    /**
    * Returns session id.
    * This method should be called only for group info type.
    *
    * @return string
    */
    public function getSessionId(): string
    {
        return vscr_ratchet_group_message_get_session_id_php($this->ctx);
    }

    /**
    * Returns message counter in current epoch.
    *
    * @return int
    */
    public function getCounter(): int
    {
        return vscr_ratchet_group_message_get_counter_php($this->ctx);
    }

    /**
    * Returns message epoch.
    *
    * @return int
    */
    public function getEpoch(): int
    {
        return vscr_ratchet_group_message_get_epoch_php($this->ctx);
    }

    /**
    * Buffer len to serialize this class.
    *
    * @return int
    */
    public function serializeLen(): int
    {
        return vscr_ratchet_group_message_serialize_len_php($this->ctx);
    }

    /**
    * Serializes instance.
    *
    * @return string
    */
    public function serialize(): string
    {
        return vscr_ratchet_group_message_serialize_php($this->ctx);
    }

    /**
    * Deserializes instance.
    *
    * @param string $input
    * @return RatchetGroupMessage
    */
    public static function deserialize(string $input): RatchetGroupMessage
    {
        $ctx = vscr_ratchet_group_message_deserialize_php($input);
        return new RatchetGroupMessage($ctx);
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
