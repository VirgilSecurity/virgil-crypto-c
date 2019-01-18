#ifndef SHA256_H
#define SHA256_H

#include <virgil/crypto/foundation/vscf_sha256.h>

#include "hash.h"
#include "utils.h"

class Sha256 : public Hash {
public:
  static void Init(v8::Local<v8::Object> exports);
  vscf_impl_t* GetImplementation();
private:
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Hash(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Start(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Update(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Finish(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
  Sha256();
  ~Sha256();
  vscf_sha256_t* sha256;
};

#endif
