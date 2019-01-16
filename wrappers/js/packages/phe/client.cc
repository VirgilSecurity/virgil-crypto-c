#include "client.h"

Nan::Persistent<v8::Function> Client::constructor;

void Client::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;
  v8::Local<v8::FunctionTemplate> function_template = Nan::New<v8::FunctionTemplate>(New);
  function_template->SetClassName(Nan::New("Client").ToLocalChecked());
  function_template->InstanceTemplate()->SetInternalFieldCount(1);
  Nan::SetPrototypeMethod(function_template, "enrollAccount", EnrollAccount);
  Nan::SetPrototypeMethod(function_template, "passwordVerifyRequest", PasswordVerifyRequest);
  Nan::SetPrototypeMethod(function_template, "verifyServerResponse", VerifyServerResponse);
  constructor.Reset(function_template->GetFunction());
  exports->Set(Nan::New<v8::String>("Client").ToLocalChecked(), function_template->GetFunction());
}

void Client::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    Client* client = new Client();
    client->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    v8::Local<v8::Function> cons = Nan::New<v8::Function>(constructor);
    info.GetReturnValue().Set(Nan::NewInstance(cons).ToLocalChecked());
  }
}

void Client::EnrollAccount(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> client_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  v8::Local<v8::Value> enrollment_response_node_buffer = info[2];
  v8::Local<v8::Value> password_node_buffer = info[3];
  if (
    info.Length() != 4 ||
    !client_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject() ||
    !enrollment_response_node_buffer->IsObject() ||
    !password_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  vsc_data_t client_private_key = utils::NodeBufferToVirgilData(client_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  vsc_data_t enrollment_response = utils::NodeBufferToVirgilData(enrollment_response_node_buffer);
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  vsce_phe_client_t* phe_client = vsce_phe_client_new();
  vsce_error_t error = vsce_phe_client_set_keys(phe_client, client_private_key, server_public_key);
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_set_keys' failed");
    return;
  }
  size_t enrollment_record_len = vsce_phe_client_enrollment_record_len(phe_client);
  vsc_buffer_t* enrollment_record = vsc_buffer_new_with_capacity(enrollment_record_len);
  vsc_buffer_t* account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
  error = vsce_phe_client_enroll_account(
    phe_client,
    enrollment_response,
    password,
    enrollment_record,
    account_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_enroll_account' failed");
    return;
  }
  vsce_phe_client_destroy(&phe_client);
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  result->Set(
    Nan::New<v8::String>("enrollmentRecord").ToLocalChecked(),
    utils::GetNodeBuffer(enrollment_record).ToLocalChecked()
  );
  result->Set(
    Nan::New<v8::String>("accountKey").ToLocalChecked(),
    utils::GetNodeBuffer(account_key).ToLocalChecked()
  );
  info.GetReturnValue().Set(result);
}

void Client::PasswordVerifyRequest(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> client_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  v8::Local<v8::Value> enrollment_record_node_buffer = info[2];
  v8::Local<v8::Value> password_node_buffer = info[3];
  if (
    info.Length() != 4 ||
    !client_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject() ||
    !enrollment_record_node_buffer->IsObject() ||
    !password_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  vsc_data_t client_private_key = utils::NodeBufferToVirgilData(client_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  vsc_data_t enrollment_record = utils::NodeBufferToVirgilData(enrollment_record_node_buffer);
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  vsce_phe_client_t* phe_client = vsce_phe_client_new();
  vsce_error_t error = vsce_phe_client_set_keys(phe_client, client_private_key, server_public_key);
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_set_keys' failed");
    return;
  }
  size_t verify_password_request_len = vsce_phe_client_verify_password_request_len(phe_client);
  vsc_buffer_t* verify_password_request = vsc_buffer_new_with_capacity(
    verify_password_request_len
  );
  error = vsce_phe_client_create_verify_password_request(
    phe_client,
    password,
    enrollment_record,
    verify_password_request
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_create_verify_password_request' failed");
    return;
  }
  vsce_phe_client_destroy(&phe_client);
  info.GetReturnValue().Set(utils::GetNodeBuffer(verify_password_request).ToLocalChecked());
}

void Client::VerifyServerResponse(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> client_private_key_node_buffer = info[0];
  v8::Local<v8::Value> server_public_key_node_buffer = info[1];
  v8::Local<v8::Value> password_node_buffer = info[2];
  v8::Local<v8::Value> enrollment_record_node_buffer = info[3];
  v8::Local<v8::Value> verify_password_response_node_buffer = info[4];
  if (
    info.Length() != 5 ||
    !client_private_key_node_buffer->IsObject() ||
    !server_public_key_node_buffer->IsObject() ||
    !password_node_buffer->IsObject() ||
    !enrollment_record_node_buffer->IsObject() ||
    !verify_password_response_node_buffer->IsObject()
  ) {
    Nan::ThrowTypeError("Invalid arguments");
    return;
  }
  vsc_data_t client_private_key = utils::NodeBufferToVirgilData(client_private_key_node_buffer);
  vsc_data_t server_public_key = utils::NodeBufferToVirgilData(server_public_key_node_buffer);
  vsc_data_t password = utils::NodeBufferToVirgilData(password_node_buffer);
  vsc_data_t enrollment_record = utils::NodeBufferToVirgilData(enrollment_record_node_buffer);
  vsc_data_t verify_password_response = utils::NodeBufferToVirgilData(
    verify_password_response_node_buffer
  );
  vsce_phe_client_t* phe_client = vsce_phe_client_new();
  vsce_error_t error = vsce_phe_client_set_keys(phe_client, client_private_key, server_public_key);
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_set_keys' failed");
    return;
  }
  vsc_buffer_t* account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
  error = vsce_phe_client_check_response_and_decrypt(
    phe_client,
    password,
    enrollment_record,
    verify_password_response,
    account_key
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_client_check_response_and_decrypt' failed");
    return;
  }
  vsce_phe_client_destroy(&phe_client);
  info.GetReturnValue().Set(utils::GetNodeBuffer(account_key).ToLocalChecked());
}
