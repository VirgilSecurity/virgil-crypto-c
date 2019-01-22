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

#include "kdf1.h"

void Kdf1::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(Kdf1::New);
  function_template->SetClassName(Nan::New("Kdf1").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "useHash", Kdf1::UseHash);
  Nan::SetPrototypeMethod(function_template, "derive", Kdf1::Derive);
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Kdf1").ToLocalChecked(), function_template->GetFunction());
}

void Kdf1::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    v8::Local<v8::Value> hash_binding_object = info[0];
    if (info.Length() != 1 || !hash_binding_object->IsObject()) {
      Nan::ThrowTypeError("Invalid arguments");
      return;
    }
    Hash* hash = Nan::ObjectWrap::Unwrap<Hash>(
      Nan::To<v8::Object>(hash_binding_object).ToLocalChecked()
    );
    Kdf1* kdf1 = new Kdf1(hash);
    kdf1->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    Nan::ThrowTypeError("Class constructor cannot be invoked without 'new'");
  }
}

void Kdf1::UseHash(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> hash_binding_object = info[0];
  if (info.Length() != 1 || !hash_binding_object->IsObject()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Kdf1* kdf1 = Nan::ObjectWrap::Unwrap<Kdf1>(info.Holder());
  Hash* hash = Nan::ObjectWrap::Unwrap<Hash>(
    Nan::To<v8::Object>(hash_binding_object).ToLocalChecked()
  );
  vscf_kdf1_release_hash(kdf1->kdf1);
  vscf_kdf1_use_hash(kdf1->kdf1, hash->GetImplementation());
}

void Kdf1::Derive(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> data_node_buffer = info[0];
  v8::Local<v8::Value> key_len_number = info[1];
  if (info.Length() != 2 || !data_node_buffer->IsObject() || !key_len_number->IsUint32()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Kdf1* kdf1 = Nan::ObjectWrap::Unwrap<Kdf1>(info.Holder());
  vsc_data_t data = utils::NodeBufferToVirgilData(data_node_buffer);
  size_t key_len = Nan::To<uint32_t>(key_len_number).FromJust();
  vsc_buffer_t* key = vsc_buffer_new_with_capacity(key_len);
  vscf_kdf1_derive(kdf1->kdf1, data, key_len, key);
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(key).ToLocalChecked());
}

Nan::Persistent<v8::Function> Kdf1::constructor;

Kdf1::Kdf1(Hash* hash) {
  kdf1 = vscf_kdf1_new();
  vscf_kdf1_use_hash(kdf1, hash->GetImplementation());
}

Kdf1::~Kdf1() {
  vscf_kdf1_release_hash(kdf1);
  vscf_kdf1_destroy(&kdf1);
}
