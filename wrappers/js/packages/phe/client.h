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
  static void EnrollAccount(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void PasswordVerifyRequest(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void VerifyServerResponse(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
};

#endif
