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

/**
* Add and/or remove recipients and it's parameters within message info.
*
* Usage:
* 1. Unpack binary message info that was obtained from RecipientCipher.
* 2. Add and/or remove key recipients.
* 3. Pack MessagInfo to the binary data.
*/
class MessageInfoEditor
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
        $this->ctx = is_null($ctx) ? vscf_message_info_editor_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_message_info_editor_delete_php($this->ctx);
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_message_info_editor_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * Set dependencies to it's defaults.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_message_info_editor_setup_defaults_php($this->ctx);
    }

    /**
    * Unpack serialized message info.
    *
    * Note that recipients can only be removed but not added.
    * Note, use "unlock" method to be able to add new recipients as well.
    *
    * @param string $messageInfoData
    * @return void
    * @throws \Exception
    */
    public function unpack(string $messageInfoData): void
    {
        vscf_message_info_editor_unpack_php($this->ctx, $messageInfoData);
    }

    /**
    * Decrypt encryption key this allows adding new recipients.
    *
    * @param string $ownerRecipientId
    * @param PrivateKey $ownerPrivateKey
    * @return void
    * @throws \Exception
    */
    public function unlock(string $ownerRecipientId, PrivateKey $ownerPrivateKey): void
    {
        vscf_message_info_editor_unlock_php($this->ctx, $ownerRecipientId, , $ownerPrivateKey->getCtx());
    }

    /**
    * Add recipient defined with id and public key.
    *
    * @param string $recipientId
    * @param PublicKey $publicKey
    * @return void
    * @throws \Exception
    */
    public function addKeyRecipient(string $recipientId, PublicKey $publicKey): void
    {
        vscf_message_info_editor_add_key_recipient_php($this->ctx, $recipientId, , $publicKey->getCtx());
    }

    /**
    * Remove recipient with a given id.
    * Return false if recipient with given id was not found.
    *
    * @param string $recipientId
    * @return bool
    */
    public function removeKeyRecipient(string $recipientId): bool
    {
        return vscf_message_info_editor_remove_key_recipient_php($this->ctx, $recipientId);
    }

    /**
    * Remove all existent recipients.
    *
    * @return void
    */
    public function removeAll(): void
    {
        vscf_message_info_editor_remove_all_php($this->ctx);
    }

    /**
    * Return length of serialized message info.
    * Actual length can be obtained right after applying changes.
    *
    * @return int
    */
    public function packedLen(): int
    {
        return vscf_message_info_editor_packed_len_php($this->ctx);
    }

    /**
    * Return serialized message info.
    * Precondition: this method can be called after "apply".
    *
    * @return string
    */
    public function pack(): string
    {
        return vscf_message_info_editor_pack_php($this->ctx);
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
