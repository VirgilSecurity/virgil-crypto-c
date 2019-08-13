// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    (1) Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
//    (2) Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
//    (3) Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
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

#include "sha256.h"

void Sha256::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(Sha256::New);
  function_template->SetClassName(Nan::New("Sha256").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "hash", Sha256::Hash);
  Nan::SetPrototypeMethod(function_template, "start", Sha256::Start);
  Nan::SetPrototypeMethod(function_template, "update", Sha256::Update);
  Nan::SetPrototypeMethod(function_template, "finish", Sha256::Finish);
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Sha256").ToLocalChecked(), function_template->GetFunction());
}

vscf_impl_t* Sha256::GetImplementation() {
  return vscf_sha256_impl(sha256);
}

void Sha256::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    Sha256* sha256 = new Sha256();
    sha256->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    Nan::ThrowTypeError("Class constructor cannot be invoked without 'new'");
  }
}

void Sha256::Hash(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> data_node_buffer = info[0];
  if (info.Length() != 1 || !data_node_buffer->IsObject()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  vsc_data_t data = utils::NodeBufferToVirgilData(data_node_buffer);
  utils::BufferWithBytes digest = utils::CreateBufferWithBytes(vscf_sha256_DIGEST_LEN);
  vscf_sha256_hash(data, digest.buffer);
  info.GetReturnValue().Set(utils::BufferWithBytesToNodeBuffer(digest).ToLocalChecked());
  vsc_buffer_destroy(&digest.buffer);
}

void Sha256::Start(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Sha256* sha256 = ObjectWrap::Unwrap<Sha256>(info.Holder());
  vscf_sha256_start(sha256->sha256);
}

void Sha256::Update(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> data_node_buffer = info[0];
  if (info.Length() != 1 || !data_node_buffer->IsObject()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Sha256* sha256 = ObjectWrap::Unwrap<Sha256>(info.Holder());
  vsc_data_t data = utils::NodeBufferToVirgilData(data_node_buffer);
  vscf_sha256_update(sha256->sha256, data);
}

void Sha256::Finish(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Sha256* sha256 = ObjectWrap::Unwrap<Sha256>(info.Holder());
  utils::BufferWithBytes digest = utils::CreateBufferWithBytes(vscf_sha256_DIGEST_LEN);
  vscf_sha256_finish(sha256->sha256, digest.buffer);
  info.GetReturnValue().Set(utils::BufferWithBytesToNodeBuffer(digest).ToLocalChecked());
  vsc_buffer_destroy(&digest.buffer);
}

Nan::Persistent<v8::Function> Sha256::constructor;

Sha256::Sha256() {
  sha256 = vscf_sha256_new();
}

Sha256::~Sha256() {
  vscf_sha256_destroy(&sha256);
}
