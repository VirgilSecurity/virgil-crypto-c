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
