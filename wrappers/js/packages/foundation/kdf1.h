#ifndef KDF1_H
#define KDF1_H

#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/vscf_kdf1.h>

#include "hash.h"
#include "kdf.h"
#include "utils.h"

class Kdf1 : public Kdf {
public:
  static void Init(v8::Local<v8::Object> exports);
private:
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void UseHash(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Derive(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
  Kdf1(Hash* hash);
  ~Kdf1();
  vscf_kdf1_t* kdf1;
};

#endif
