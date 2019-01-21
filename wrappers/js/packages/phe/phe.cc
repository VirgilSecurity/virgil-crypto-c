#include <nan.h>

#include "cipher.h"
#include "client.h"
#include "server.h"

void InitAll(v8::Local<v8::Object> exports) {
  Cipher::Init(exports);
  Client::Init(exports);
  Server::Init(exports);
}

NODE_MODULE(addon, InitAll)
