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

#include "client.h"

void Client::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(Client::New);
  function_template->SetClassName(Nan::New("Client").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "setKeys", Client::SetKeys);
  Nan::SetPrototypeMethod(
    function_template,
    "generateClientPrivateKey",
    Client::GenerateClientPrivateKey
  );
  Nan::SetPrototypeMethod(function_template, "enrollAccount", Client::EnrollAccount);
  Nan::SetPrototypeMethod(
    function_template,
    "createVerifyPasswordRequest",
    Client::CreateVerifyPasswordRequest
  );
  Nan::SetPrototypeMethod(
    function_template,
    "checkResponseAndDecrypt",
    Client::CheckResponseAndDecrypt
  );
  Nan::SetPrototypeMethod(function_template, "rotateKeys", Client::RotateKeys);
  Nan::SetPrototypeMethod(
    function_template,
    "updateEnrollmentRecord",
    Client::UpdateEnrollmentRecord
  );
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Client").ToLocalChecked(), function_template->GetFunction());
}

void Client::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    Client* client = new Client();
    client->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    Nan::ThrowTypeError("Class constructor cannot be invoked without 'new'");
  }
}

void Client::SetKeys(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> client_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !client_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t client_private_key = utils::NodeBufferToVirgilData(client_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  vsce_error_t error = vsce_phe_client_set_keys(
    client->phe_client,
    client_private_key,
    server_public_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_set_keys' failed");
    return;
  }
}

void Client::GenerateClientPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_buffer_t* client_private_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PRIVATE_KEY_LENGTH
  );
  vsce_error_t error = vsce_phe_client_generate_client_private_key(
    client->phe_client,
    client_private_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_generate_client_private_key' failed");
    return;
  }
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(client_private_key).ToLocalChecked());
}

void Client::EnrollAccount(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> enrollment_response_node_buffer = info[0];
  v8::Local<v8::Value> password_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !enrollment_response_node_buffer->IsObject() ||
    !password_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t enrollment_response = utils::NodeBufferToVirgilData(enrollment_response_node_buffer);
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  size_t enrollment_record_len = vsce_phe_client_enrollment_record_len(client->phe_client);
  vsc_buffer_t* enrollment_record = vsc_buffer_new_with_capacity(enrollment_record_len);
  vsc_buffer_t* account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
  vsce_error_t error = vsce_phe_client_enroll_account(
    client->phe_client,
    enrollment_response,
    password,
    enrollment_record,
    account_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_enroll_account' failed");
    return;
  }
  Nan::EscapableHandleScope scope;
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  result->Set(
    Nan::New<v8::String>("enrollmentRecord").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(enrollment_record).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("accountKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(account_key).ToLocalChecked()
  );
  info.GetReturnValue().Set(scope.Escape(result));
}

void Client::CreateVerifyPasswordRequest(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> enrollment_record_node_buffer = info[0];
  v8::Local<v8::Value> password_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !enrollment_record_node_buffer->IsObject() ||
    !password_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t enrollment_record = utils::NodeBufferToVirgilData(enrollment_record_node_buffer);
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  size_t verify_password_request_len = vsce_phe_client_verify_password_request_len(
    client->phe_client
  );
  vsc_buffer_t* verify_password_request = vsc_buffer_new_with_capacity(
    verify_password_request_len
  );
  vsce_error_t error = vsce_phe_client_create_verify_password_request(
    client->phe_client,
    password,
    enrollment_record,
    verify_password_request
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_create_verify_password_request' failed");
    return;
  }
  info.GetReturnValue().Set(
    utils::VirgilBufferToNodeBuffer(verify_password_request).ToLocalChecked()
  );
}

void Client::CheckResponseAndDecrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> password_node_buffer = info[0];
  v8::Local<v8::Value> enrollment_record_node_buffer = info[1];
  v8::Local<v8::Value> verify_password_response_node_buffer = info[2];
  if (
    info.Length() != 3 ||
    !password_node_buffer->IsObject() ||
    !enrollment_record_node_buffer->IsObject() ||
    !verify_password_response_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  vsc_data_t enrollment_record = utils::NodeBufferToVirgilData(enrollment_record_node_buffer);
  vsc_data_t verify_password_response = utils::NodeBufferToVirgilData(
    verify_password_response_node_buffer
  );
  vsc_buffer_t* account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
  vsce_error_t error = vsce_phe_client_check_response_and_decrypt(
    client->phe_client,
    password,
    enrollment_record,
    verify_password_response,
    account_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_check_response_and_decrypt' failed");
    return;
  }
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(account_key).ToLocalChecked());
}

void Client::RotateKeys(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> update_token_node_buffer = info[0];
  if (info.Length() != 1 || !update_token_node_buffer->IsObject()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t update_token = utils::NodeBufferToVirgilData(update_token_node_buffer);
  vsc_buffer_t* new_client_private_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PRIVATE_KEY_LENGTH
  );
  vsc_buffer_t* new_server_public_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PUBLIC_KEY_LENGTH
  );
  vsce_error_t error = vsce_phe_client_rotate_keys(
    client->phe_client,
    update_token,
    new_client_private_key,
    new_server_public_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_rotate_keys' failed");
    return;
  }
  Nan::EscapableHandleScope scope;
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  result->Set(
    Nan::New<v8::String>("newClientPrivateKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(new_client_private_key).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("newServerPublicKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(new_server_public_key).ToLocalChecked()
  );
  info.GetReturnValue().Set(scope.Escape(result));
}

void Client::UpdateEnrollmentRecord(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> enrollment_record_node_buffer = info[0];
  v8::Local<v8::Value> update_token_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !enrollment_record_node_buffer->IsObject() ||
    !update_token_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Client* client = Nan::ObjectWrap::Unwrap<Client>(info.Holder());
  vsc_data_t enrollment_record = utils::NodeBufferToVirgilData(enrollment_record_node_buffer);
  vsc_data_t update_token = utils::NodeBufferToVirgilData(update_token_node_buffer);
  size_t enrollment_record_len = vsce_phe_client_enrollment_record_len(client->phe_client);
  vsc_buffer_t* new_enrollment_record = vsc_buffer_new_with_capacity(enrollment_record_len);
  vsce_error_t error = vsce_phe_client_update_enrollment_record(
    client->phe_client,
    enrollment_record,
    update_token,
    new_enrollment_record
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_update_enrollment_record' failed");
    return;
  }
  info.GetReturnValue().Set(
    utils::VirgilBufferToNodeBuffer(new_enrollment_record).ToLocalChecked()
  );
}

Nan::Persistent<v8::Function> Client::constructor;

Client::Client() {
  phe_client = vsce_phe_client_new();
}

Client::~Client() {
  vsce_phe_client_destroy(&phe_client);
}
