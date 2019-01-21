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
  vsc_buffer_t* digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);
  vscf_sha256_hash(data, digest);
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(digest).ToLocalChecked());
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
  vsc_buffer_t* digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);
  vscf_sha256_finish(sha256->sha256, digest);
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(digest).ToLocalChecked());
}

Nan::Persistent<v8::Function> Sha256::constructor;

Sha256::Sha256() {
  sha256 = vscf_sha256_new();
}

Sha256::~Sha256() {
  vscf_sha256_destroy(&sha256);
}
