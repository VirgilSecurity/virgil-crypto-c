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


const precondition = require('./precondition');

const initRatchetCommon = (Module, modules) => {
    class RatchetCommon {

        static get MAX_PLAIN_TEXT_LEN() {
            return 30000;
        }

        get MAX_PLAIN_TEXT_LEN() {
            return 30000;
        }

        static get MAX_MESSAGE_LEN() {
            return 35583;
        }

        get MAX_MESSAGE_LEN() {
            return 35583;
        }

        static get KEY_ID_LEN() {
            return 8;
        }

        get KEY_ID_LEN() {
            return 8;
        }

        static get PARTICIPANT_ID_LEN() {
            return 32;
        }

        get PARTICIPANT_ID_LEN() {
            return 32;
        }

        static get SESSION_ID_LEN() {
            return 32;
        }

        get SESSION_ID_LEN() {
            return 32;
        }

        static get MAX_PARTICIPANTS_COUNT() {
            return 100;
        }

        get MAX_PARTICIPANTS_COUNT() {
            return 100;
        }

        static get MIN_PARTICIPANTS_COUNT() {
            return 2;
        }

        get MIN_PARTICIPANTS_COUNT() {
            return 2;
        }

        static get MAX_GROUP_MESSAGE_LEN() {
            return 32918;
        }

        get MAX_GROUP_MESSAGE_LEN() {
            return 32918;
        }

    }

    return RatchetCommon;
};

module.exports = initRatchetCommon;
