#include <nan.h>

#include "kdf1.h"
#include "sha256.h"

void InitAll(v8::Local<v8::Object> exports) {
  Kdf1::Init(exports);
  Sha256::Init(exports);
}

NODE_MODULE(addon, InitAll)
