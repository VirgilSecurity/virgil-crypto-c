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

#ifndef CLIENT_H
#define CLIENT_H

#include <nan.h>
#include <virgil/crypto/phe/vsce_phe_client.h>

#include "utils.h"

class Client : public Nan::ObjectWrap {
public:
  static void Init(v8::Local<v8::Object> exports);
private:
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void SetKeys(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GenerateClientPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void EnrollAccount(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void CreateVerifyPasswordRequest(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void CheckResponseAndDecrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void RotateKeys(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void UpdateEnrollmentRecord(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
  Client();
  ~Client();
  vsce_phe_client_t* phe_client;
};

#endif
