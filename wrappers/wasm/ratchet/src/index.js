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


const RatchetModule = require('libratchet');

const initFoundationInterface = require('../foundation/FoundationInterface');
const initCtrDrbg = require('../foundation/CtrDrbg');
const initHmac = require('../foundation/Hmac');
const initHkdf = require('../foundation/Hkdf');
const initSha512 = require('../foundation/Sha512');
const initRatchetError = require('./RatchetError');
const initMsgType = require('./MsgType');
const initGroupMsgType = require('./GroupMsgType');
const initRatchetCommon = require('./RatchetCommon');
const initRatchetKeyId = require('./RatchetKeyId');
const initRatchetMessage = require('./RatchetMessage');
const initRatchetSession = require('./RatchetSession');
const initRatchetGroupMessage = require('./RatchetGroupMessage');
const initRatchetGroupTicket = require('./RatchetGroupTicket');
const initRatchetGroupSession = require('./RatchetGroupSession');

const RatchetModule = new RatchetModule();
let initPromise;

const initRatchet = () => {
    if (initPromise) {
        return initPromise;
    }
    initPromise = new Promise((resolve, reject) => {
        RatchetModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.FoundationInterface = initFoundationInterface(RatchetModule, modules);
            modules.CtrDrbg = initCtrDrbg(RatchetModule, modules);
            modules.Hmac = initHmac(RatchetModule, modules);
            modules.Hkdf = initHkdf(RatchetModule, modules);
            modules.Sha512 = initSha512(RatchetModule, modules);
            modules.RatchetError = initRatchetError(RatchetModule, modules);
            modules.MsgType = initMsgType(RatchetModule, modules);
            modules.GroupMsgType = initGroupMsgType(RatchetModule, modules);
            modules.RatchetCommon = initRatchetCommon(RatchetModule, modules);
            modules.RatchetKeyId = initRatchetKeyId(RatchetModule, modules);
            modules.RatchetMessage = initRatchetMessage(RatchetModule, modules);
            modules.RatchetSession = initRatchetSession(RatchetModule, modules);
            modules.RatchetGroupMessage = initRatchetGroupMessage(RatchetModule, modules);
            modules.RatchetGroupTicket = initRatchetGroupTicket(RatchetModule, modules);
            modules.RatchetGroupSession = initRatchetGroupSession(RatchetModule, modules);
            resolve(modules);
        };

        RatchetModule.onAbort = message => {
            reject(new Error(message));
        };
    });
    return initPromise;
};
module.exports = initRatchet;
