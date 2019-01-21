#ifndef CIPHER_H
#define CIPHER_H

#include <nan.h>
#include <virgil/crypto/phe/vsce_phe_cipher.h>

#include "utils.h"

class Cipher : public Nan::ObjectWrap {
public:
  static void Init(v8::Local<v8::Object> exports);
private:
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Decrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
  Cipher();
  ~Cipher();
  vsce_phe_cipher_t* phe_cipher;
};

#endif
