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


const precondition = require('./precondition');

const initKeyAlgFactory = (Module, modules) => {
    class KeyAlgFactory {

        static createFromAlgId(algId, random) {
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            const proxyResult = Module._vscf_key_alg_factory_create_from_alg_id(algId, random.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        static createFromKey(key, random) {
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            const proxyResult = Module._vscf_key_alg_factory_create_from_key(key.ctxPtr, random.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        static createFromRawPublicKey(publicKey, random) {
            precondition.ensureClass('publicKey', publicKey, modules.RawPublicKey);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            const proxyResult = Module._vscf_key_alg_factory_create_from_raw_public_key(publicKey.ctxPtr, random.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        static createFromRawPrivateKey(privateKey, random) {
            precondition.ensureClass('privateKey', privateKey, modules.RawPrivateKey);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            const proxyResult = Module._vscf_key_alg_factory_create_from_raw_private_key(privateKey.ctxPtr, random.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

    }

    return KeyAlgFactory;
};

module.exports = initKeyAlgFactory;
