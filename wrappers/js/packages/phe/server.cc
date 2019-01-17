#include "server.h"

void Server::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(New);
  function_template->SetClassName(Nan::New("Server").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "generateServerKeyPair", GenerateServerKeyPair);
  Nan::SetPrototypeMethod(function_template, "getEnrollment", GetEnrollment);
  Nan::SetPrototypeMethod(function_template, "verifyPassword", VerifyPassword);
  Nan::SetPrototypeMethod(function_template, "rotateKeys", RotateKeys);
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Server").ToLocalChecked(), function_template->GetFunction());
}

void Server::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    Server* server = new Server();
    server->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    Nan::ThrowTypeError("Class constructor cannot be invoked without 'new'");
  }
}

void Server::GenerateServerKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Server* server = ObjectWrap::Unwrap<Server>(info.Holder());
  vsc_buffer_t* server_private_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PRIVATE_KEY_LENGTH
  );
  vsc_buffer_t* server_public_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PUBLIC_KEY_LENGTH
  );
  vsce_error_t error = vsce_phe_server_generate_server_key_pair(
    server->phe_server,
    server_private_key,
    server_public_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_server_generate_server_key_pair' failed");
    return;
  }
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  result->Set(
    Nan::New<v8::String>("serverPrivateKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(server_private_key).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("serverPublicKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(server_public_key).ToLocalChecked()
  );
  info.GetReturnValue().Set(result);
}

void Server::GetEnrollment(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> server_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  if (
    info.Length() != 2 ||
    !server_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Server* server = ObjectWrap::Unwrap<Server>(info.Holder());
  vsc_data_t server_private_key = utils::NodeBufferToVirgilData(server_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  size_t enrollment_response_len = vsce_phe_server_enrollment_response_len(server->phe_server);
  vsc_buffer_t* enrollment_response = vsc_buffer_new_with_capacity(enrollment_response_len);
  vsce_error_t error = vsce_phe_server_get_enrollment(
    server->phe_server,
    server_private_key,
    server_public_key,
    enrollment_response
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_server_get_enrollment' failed");
    return;
  }
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(enrollment_response).ToLocalChecked());
}

void Server::VerifyPassword(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> server_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  v8::Local<v8::Value> verify_password_request_node_buffer = info[2];
  if (
    info.Length() != 3 ||
    !server_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject() ||
    !verify_password_request_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Server* server = ObjectWrap::Unwrap<Server>(info.Holder());
  vsc_data_t server_private_key = utils::NodeBufferToVirgilData(server_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  vsc_data_t verify_password_request = utils::NodeBufferToVirgilData(
    verify_password_request_node_buffer
  );
  size_t verify_password_response_len = vsce_phe_server_verify_password_response_len(
    server->phe_server
  );
  vsc_buffer_t* verify_password_response = vsc_buffer_new_with_capacity(
    verify_password_response_len
  );
  vsce_error_t error = vsce_phe_server_verify_password(
    server->phe_server,
    server_private_key,
    server_public_key,
    verify_password_request,
    verify_password_response
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_server_verify_password' failed");
    return;
  }
  info.GetReturnValue().Set(
    utils::VirgilBufferToNodeBuffer(verify_password_response).ToLocalChecked()
  );
}

void Server::RotateKeys(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> server_private_key_node_buffer = info[0];
  if (info.Length() != 1 || !server_private_key_node_buffer->IsObject()) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  Server* server = ObjectWrap::Unwrap<Server>(info.Holder());
  vsc_data_t server_private_key = utils::NodeBufferToVirgilData(server_private_key_node_buffer);
  vsc_buffer_t* new_server_private_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PRIVATE_KEY_LENGTH
  );
  vsc_buffer_t* new_server_public_key = vsc_buffer_new_with_capacity(
    vsce_phe_common_PHE_PUBLIC_KEY_LENGTH
  );
  size_t update_token_len = vsce_phe_server_update_token_len(server->phe_server);
  vsc_buffer_t* update_token = vsc_buffer_new_with_capacity(update_token_len);
  vsce_error_t error = vsce_phe_server_rotate_keys(
    server->phe_server,
    server_private_key,
    new_server_private_key,
    new_server_public_key,
    update_token
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_server_rotate_keys' failed");
    return;
  }
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  result->Set(
    Nan::New<v8::String>("newServerPrivateKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(new_server_private_key).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("newServerPublicKey").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(new_server_public_key).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("updateToken").ToLocalChecked(),
    utils::VirgilBufferToNodeBuffer(update_token).ToLocalChecked()
  );
  info.GetReturnValue().Set(result);
}

Nan::Persistent<v8::Function> Server::constructor;

Server::Server() {
  phe_server = vsce_phe_server_new();
}

Server::~Server() {
  vsce_phe_server_destroy(&phe_server);
}
