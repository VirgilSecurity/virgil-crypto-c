// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <virgil/crypto/foundation/kek_recipient_info_list.hpp>
#include <virgil/crypto/foundation/vscf_kek_recipient_info_list.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/kek_recipient_info.hpp>

namespace virgil::crypto::foundation {

KekRecipientInfoList::KekRecipientInfoList() : c_ctx_(vscf_kek_recipient_info_list_new()) {}

KekRecipientInfoList::KekRecipientInfoList(vscf_kek_recipient_info_list_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

KekRecipientInfoList::KekRecipientInfoList(const KekRecipientInfoList& other) : c_ctx_(vscf_kek_recipient_info_list_shallow_copy(other.c_ctx_)) {}

KekRecipientInfoList::KekRecipientInfoList(KekRecipientInfoList&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

KekRecipientInfoList& KekRecipientInfoList::operator=(const KekRecipientInfoList& other) {
    if (this != &other) {
        vscf_kek_recipient_info_list_delete(c_ctx_);
        c_ctx_ = vscf_kek_recipient_info_list_shallow_copy(other.c_ctx_);
    }
    return *this;
}

KekRecipientInfoList& KekRecipientInfoList::operator=(KekRecipientInfoList&& other) noexcept {
    if (this != &other) {
        vscf_kek_recipient_info_list_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

KekRecipientInfoList::~KekRecipientInfoList() { vscf_kek_recipient_info_list_delete(c_ctx_); }

vscf_kek_recipient_info_list_t* KekRecipientInfoList::c_ctx() const noexcept { return c_ctx_; }

bool KekRecipientInfoList::has_item() const {
    auto proxy_result = vscf_kek_recipient_info_list_has_item(c_ctx_);
    return proxy_result;
}

KekRecipientInfo KekRecipientInfoList::item() const {
    auto proxy_result = vscf_kek_recipient_info_list_item(c_ctx_);
    return KekRecipientInfo(vscf_kek_recipient_info_shallow_copy(const_cast<vscf_kek_recipient_info_t*>(proxy_result)));
}

bool KekRecipientInfoList::has_next() const {
    auto proxy_result = vscf_kek_recipient_info_list_has_next(c_ctx_);
    return proxy_result;
}

KekRecipientInfoList KekRecipientInfoList::next() const {
    auto proxy_result = vscf_kek_recipient_info_list_next(c_ctx_);
    return KekRecipientInfoList(vscf_kek_recipient_info_list_shallow_copy(const_cast<vscf_kek_recipient_info_list_t*>(proxy_result)));
}

bool KekRecipientInfoList::has_prev() const {
    auto proxy_result = vscf_kek_recipient_info_list_has_prev(c_ctx_);
    return proxy_result;
}

KekRecipientInfoList KekRecipientInfoList::prev() const {
    auto proxy_result = vscf_kek_recipient_info_list_prev(c_ctx_);
    return KekRecipientInfoList(vscf_kek_recipient_info_list_shallow_copy(const_cast<vscf_kek_recipient_info_list_t*>(proxy_result)));
}

void KekRecipientInfoList::clear() {
    vscf_kek_recipient_info_list_clear(c_ctx_);
}

}  // namespace virgil::crypto::foundation
