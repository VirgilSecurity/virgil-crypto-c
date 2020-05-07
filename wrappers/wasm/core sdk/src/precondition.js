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


function ensureNumber(arg, value) {
    if (!(typeof value === 'number' || value instanceof Number)) {
        throw new TypeError(`'${arg}' is not a number`);
    }
    if (Number.isNaN(value)) {
        throw new TypeError(`'${arg}' is NaN`);
    }
    if (value === Infinity) {
        throw new TypeError(`'${arg}' is Infinity`);
    }
    if (value === -Infinity) {
        throw new TypeError(`'${arg}' is -Infinity`);
    }
}

function ensureNotNull(arg, value) {
    ensureNumber(arg, value);

    if (value == 0) {
        throw new TypeError(`'${arg}' is NULL`);
    }
}

function ensureString(arg, value) {
    if (!(typeof value === 'string' || value instanceof String)) {
        throw new TypeError(`'${arg}' is not a string`);
    }
}

function ensureBoolean(arg, value) {
    if (typeof value !== 'boolean') {
        throw new TypeError(`'${arg}' is not a boolean`);
    }
}

function ensureByteArray(arg, value) {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`'${arg}' is not an Uint8Array`);
    }
}

function ensureClass(arg, value, cls) {
    if (!(value instanceof cls)) {
        throw new TypeError(`'${arg}' is not an instance of the class ${cls.name}`);
    }
    ensureNotNull(arg, value.ctxPtr);
}

function ensureImplementInterface(arg, value, interfaceName, interfaceTag, interfaceChecker) {
    ensureNotNull(arg, value.ctxPtr);
    if (!interfaceChecker.isImplemented(value.ctxPtr, interfaceTag)) {
        throw new TypeError(`'${arg}' does not implement interface '${interfaceName}'`);
    }
}

module.exports.ensureNumber = ensureNumber;
module.exports.ensureString = ensureString;
module.exports.ensureBoolean = ensureBoolean;
module.exports.ensureByteArray = ensureByteArray;
module.exports.ensureClass = ensureClass;
module.exports.ensureNotNull = ensureNotNull;
module.exports.ensureImplementInterface = ensureImplementInterface;
