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


const precondition = require('./precondition');

const initRatchetGroupTicket = (Module, modules) => {
    /**
     * Group ticket used to start group session or change participants.
     */
    class RatchetGroupTicket {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RatchetGroupTicket';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscr_ratchet_group_ticket_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        /**
         * Acquire C context by making it's shallow copy.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetGroupTicket(Module._vscr_ratchet_group_ticket_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetGroupTicket(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscr_ratchet_group_ticket_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used to generate keys
         */
        set rng(rng) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('rng', rng, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscr_ratchet_group_ticket_release_rng(this.ctxPtr)
            Module._vscr_ratchet_group_ticket_use_rng(this.ctxPtr, rng.ctxPtr)
        }

        /**
         * Setups default dependencies:
         * - RNG: CTR DRBG
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscr_ratchet_group_ticket_setup_defaults(this.ctxPtr);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Set this ticket to start new group session.
         */
        setupTicketAsNew() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscr_ratchet_group_ticket_setup_ticket_as_new(this.ctxPtr);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Add new participant to chat.
         */
        addNewParticipant(participantId, publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('participantId', participantId);
            precondition.ensureByteArray('publicKey', publicKey);

            //  Copy bytes from JS memory to the WASM memory.
            const participantIdSize = participantId.length * participantId.BYTES_PER_ELEMENT;
            const participantIdPtr = Module._malloc(participantIdSize);
            Module.HEAP8.set(participantId, participantIdPtr);

            //  Create C structure vsc_data_t.
            const participantIdCtxSize = Module._vsc_data_ctx_size();
            const participantIdCtxPtr = Module._malloc(participantIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(participantIdCtxPtr, participantIdPtr, participantIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const publicKeySize = publicKey.length * publicKey.BYTES_PER_ELEMENT;
            const publicKeyPtr = Module._malloc(publicKeySize);
            Module.HEAP8.set(publicKey, publicKeyPtr);

            //  Create C structure vsc_data_t.
            const publicKeyCtxSize = Module._vsc_data_ctx_size();
            const publicKeyCtxPtr = Module._malloc(publicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(publicKeyCtxPtr, publicKeyPtr, publicKeySize);

            try {
                const proxyResult = Module._vscr_ratchet_group_ticket_add_new_participant(this.ctxPtr, participantIdCtxPtr, publicKeyCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(participantIdPtr);
                Module._free(participantIdCtxPtr);
                Module._free(publicKeyPtr);
                Module._free(publicKeyCtxPtr);
            }
        }

        /**
         * Remove participant from chat.
         */
        removeParticipant(participantId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('participantId', participantId);

            //  Copy bytes from JS memory to the WASM memory.
            const participantIdSize = participantId.length * participantId.BYTES_PER_ELEMENT;
            const participantIdPtr = Module._malloc(participantIdSize);
            Module.HEAP8.set(participantId, participantIdPtr);

            //  Create C structure vsc_data_t.
            const participantIdCtxSize = Module._vsc_data_ctx_size();
            const participantIdCtxPtr = Module._malloc(participantIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(participantIdCtxPtr, participantIdPtr, participantIdSize);

            try {
                const proxyResult = Module._vscr_ratchet_group_ticket_remove_participant(this.ctxPtr, participantIdCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(participantIdPtr);
                Module._free(participantIdCtxPtr);
            }
        }

        /**
         * Generates message that should be sent to all participants using secure channel.
         */
        getTicketMessage() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_ticket_get_ticket_message(this.ctxPtr);

            const jsResult = modules.RatchetGroupMessage.newAndUseCContext(proxyResult);
            return jsResult;
        }
    }

    return RatchetGroupTicket;
};

module.exports = initRatchetGroupTicket;
