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
