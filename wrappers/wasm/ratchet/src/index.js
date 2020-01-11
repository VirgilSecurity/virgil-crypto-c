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


const RatchetModule = require(process.env.PROJECT_MODULE);

const initFoundationError = require('../foundation/FoundationError');
const initFoundationInterface = require('../foundation/FoundationInterface');
const initFoundationInterfaceTag = require('../foundation/FoundationInterfaceTag');
const initFoundationImplTag = require('../foundation/FoundationImplTag');
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
const initRatchetGroupParticipantsInfo = require('./RatchetGroupParticipantsInfo');
const initRatchetGroupMessage = require('./RatchetGroupMessage');
const initRatchetGroupTicket = require('./RatchetGroupTicket');
const initRatchetGroupParticipantsIds = require('./RatchetGroupParticipantsIds');
const initRatchetGroupSession = require('./RatchetGroupSession');

const initProject = () => {
    const ratchetModule = new RatchetModule();
    return new Promise((resolve, reject) => {
        ratchetModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.FoundationError = initFoundationError(ratchetModule, modules);
            modules.FoundationInterface = initFoundationInterface(ratchetModule, modules);
            modules.FoundationInterfaceTag = initFoundationInterfaceTag(ratchetModule, modules);
            modules.FoundationImplTag = initFoundationImplTag(ratchetModule, modules);
            modules.CtrDrbg = initCtrDrbg(ratchetModule, modules);
            modules.Hmac = initHmac(ratchetModule, modules);
            modules.Hkdf = initHkdf(ratchetModule, modules);
            modules.Sha512 = initSha512(ratchetModule, modules);
            modules.RatchetError = initRatchetError(ratchetModule, modules);
            modules.MsgType = initMsgType(ratchetModule, modules);
            modules.GroupMsgType = initGroupMsgType(ratchetModule, modules);
            modules.RatchetCommon = initRatchetCommon(ratchetModule, modules);
            modules.RatchetKeyId = initRatchetKeyId(ratchetModule, modules);
            modules.RatchetMessage = initRatchetMessage(ratchetModule, modules);
            modules.RatchetSession = initRatchetSession(ratchetModule, modules);
            modules.RatchetGroupParticipantsInfo = initRatchetGroupParticipantsInfo(ratchetModule, modules);
            modules.RatchetGroupMessage = initRatchetGroupMessage(ratchetModule, modules);
            modules.RatchetGroupTicket = initRatchetGroupTicket(ratchetModule, modules);
            modules.RatchetGroupParticipantsIds = initRatchetGroupParticipantsIds(ratchetModule, modules);
            modules.RatchetGroupSession = initRatchetGroupSession(ratchetModule, modules);
            resolve(modules);
        };

        ratchetModule.onAbort = message => {
            reject(new Error(message));
        };
    });
};
module.exports = initProject;
