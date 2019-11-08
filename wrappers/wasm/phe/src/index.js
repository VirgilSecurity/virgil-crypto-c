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


const PheModule = require(process.env.PROJECT_MODULE);

const initFoundationInterface = require('../foundation/FoundationInterface');
const initCtrDrbg = require('../foundation/CtrDrbg');
const initHmac = require('../foundation/Hmac');
const initHkdf = require('../foundation/Hkdf');
const initSha512 = require('../foundation/Sha512');
const initFoundationError = require('../foundation/FoundationError');
const initPheError = require('./PheError');
const initPheCommon = require('./PheCommon');
const initPheServer = require('./PheServer');
const initPheClient = require('./PheClient');
const initPheCipher = require('./PheCipher');

const initProject = () => {
    const pheModule = new PheModule();
    return new Promise((resolve, reject) => {
        pheModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.FoundationInterface = initFoundationInterface(pheModule, modules);
            modules.CtrDrbg = initCtrDrbg(pheModule, modules);
            modules.Hmac = initHmac(pheModule, modules);
            modules.Hkdf = initHkdf(pheModule, modules);
            modules.Sha512 = initSha512(pheModule, modules);
            modules.FoundationError = initFoundationError(pheModule, modules);
            modules.PheError = initPheError(pheModule, modules);
            modules.PheCommon = initPheCommon(pheModule, modules);
            modules.PheServer = initPheServer(pheModule, modules);
            modules.PheClient = initPheClient(pheModule, modules);
            modules.PheCipher = initPheCipher(pheModule, modules);
            resolve(modules);
        };

        pheModule.onAbort = message => {
            reject(new Error(message));
        };
    });
};
module.exports = initProject;
