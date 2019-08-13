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

#include "cipher.h"

void Cipher::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(Cipher::New);
  function_template->SetClassName(Nan::New("Cipher").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "encrypt", Cipher::Encrypt);
  Nan::SetPrototypeMethod(function_template, "decrypt", Cipher::Decrypt);
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Cipher").ToLocalChecked(), function_template->GetFunction());
}

void Cipher::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    Cipher* cipher = new Cipher();
    cipher->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    Nan::ThrowTypeError("Class constructor cannot be invoked without 'new'");
  }
}

void Cipher::Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> plain_text_node_buffer = info[0];
  v8::Local<v8::Value> account_key_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !plain_text_node_buffer->IsObject() ||
    !account_key_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Cipher* cipher = Nan::ObjectWrap::Unwrap<Cipher>(info.Holder());
  vsc_data_t plain_text = utils::NodeBufferToVirgilData(plain_text_node_buffer);
  vsc_data_t account_key = utils::NodeBufferToVirgilData(account_key_node_buffer);
  size_t encrypt_len = vsce_phe_cipher_encrypt_len(cipher->phe_cipher, plain_text.len);
  utils::BufferWithBytes cipher_text = utils::CreateBufferWithBytes(encrypt_len);
  vsce_error_t error = vsce_phe_cipher_encrypt(
    cipher->phe_cipher,
    plain_text,
    account_key,
    cipher_text.buffer
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    utils::CleanupBufferWithBytes(cipher_text);
    Nan::ThrowError("'vsce_phe_cipher_encrypt' failed");
    return;
  }
  info.GetReturnValue().Set(utils::BufferWithBytesToNodeBuffer(cipher_text).ToLocalChecked());
  vsc_buffer_destroy(&cipher_text.buffer);
}

void Cipher::Decrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> cipher_text_node_buffer = info[0];
  v8::Local<v8::Value> account_key_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !cipher_text_node_buffer->IsObject() ||
    !account_key_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Cipher* cipher = Nan::ObjectWrap::Unwrap<Cipher>(info.Holder());
  vsc_data_t cipher_text = utils::NodeBufferToVirgilData(cipher_text_node_buffer);
  vsc_data_t account_key = utils::NodeBufferToVirgilData(account_key_node_buffer);
  size_t decrypt_len = vsce_phe_cipher_decrypt_len(cipher->phe_cipher, cipher_text.len);
  utils::BufferWithBytes plain_text = utils::CreateBufferWithBytes(decrypt_len);
  vsce_error_t error = vsce_phe_cipher_decrypt(
    cipher->phe_cipher,
    cipher_text,
    account_key,
    plain_text.buffer
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    utils::CleanupBufferWithBytes(plain_text);
    Nan::ThrowError("'vsce_phe_cipher_decrypt' failed");
    return;
  }
  info.GetReturnValue().Set(utils::BufferWithBytesToNodeBuffer(plain_text).ToLocalChecked());
  vsc_buffer_destroy(&plain_text.buffer);
}

Nan::Persistent<v8::Function> Cipher::constructor;

Cipher::Cipher() {
  phe_cipher = vsce_phe_cipher_new();
  vsce_phe_cipher_setup_defaults(phe_cipher);
}

Cipher::~Cipher() {
  vsce_phe_cipher_destroy(&phe_cipher);
}
