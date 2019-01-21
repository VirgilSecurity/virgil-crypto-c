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
  vsc_buffer_t* cipher_text = vsc_buffer_new_with_capacity(encrypt_len);
  vsce_error_t error = vsce_phe_cipher_encrypt(
    cipher->phe_cipher,
    plain_text,
    account_key,
    cipher_text
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_cipher_encrypt' failed");
    return;
  }
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(cipher_text).ToLocalChecked());
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
  vsc_buffer_t* plain_text = vsc_buffer_new_with_capacity(decrypt_len);
  vsce_error_t error = vsce_phe_cipher_decrypt(
    cipher->phe_cipher,
    cipher_text,
    account_key,
    plain_text
  );
  if (error != vsce_error_t::vsce_SUCCESS) {
    Nan::ThrowError("'vsce_phe_cipher_decrypt' failed");
    return;
  }
  info.GetReturnValue().Set(utils::VirgilBufferToNodeBuffer(plain_text).ToLocalChecked());
}

Nan::Persistent<v8::Function> Cipher::constructor;

Cipher::Cipher() {
  phe_cipher = vsce_phe_cipher_new();
  vsce_phe_cipher_setup_defaults(phe_cipher);
}

Cipher::~Cipher() {
  vsce_phe_cipher_destroy(&phe_cipher);
}
